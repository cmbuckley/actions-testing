const https = require('https');

module.exports = async (core) => {
    const {
            HOST,
            SLACK_WEBHOOK,
            MONITOR_DOMAINS = '',
            ERROR_THRESHOLD = 7,
            WARN_THRESHOLD = 28,
            TIMEOUT = 5000,
            RETRY_ATTEMPTS = 3,
            RETRY_DELAY = 500,
        } = process.env,
        warnings = [];

    async function check(options) {
        let connectTimer;

        return new Promise(resolve => {
            https.get({
                hostname: options.hostname,
                port: 444,
                timeout: options.timeout,
                headers: {
                    host: options.domain,
                },
            }, function (response) {
                clearTimeout(connectTimer);
                const cert = response.socket.getPeerCertificate();
                this.destroy(); // cancel the connection

                if (cert === null || !Object.keys(cert).length) {
                    core.error(`No certificate found for ${options.domain}.`);
                    core.setFailed();
                } else {
                    const daysLeft = parseInt((Date.parse(cert.valid_to) - new Date().getTime()) / (1000 * 60 * 60 * 24), 10),
                        level = (daysLeft < options.errorThreshold ? 'error' : (daysLeft < options.warnThreshold ? 'warning' : 'info')),
                        colour = '\u001b[' + (daysLeft < options.errorThreshold ? 31 : (daysLeft < options.warnThreshold ? 33 : 32)) + 'm',
                        reset = '\u001b[0m';

                    core[level](`Certificate for ${options.domain} expires in ${colour}${daysLeft}${reset} days (${cert.valid_to})`);

                    if (level == 'warning') {
                        warnings.push({
                            domain: options.domain,
                            daysLeft,
                            date: cert.valid_to,
                        });
                    }

                    if (daysLeft < options.errorThreshold) {
                        core.setFailed('Certificates expire soon');
                    }
                }

                resolve();
            }).on('socket', function (socket) {
                if (socket.connecting) {
                    connectTimer = setTimeout(() => {
                        this.destroy(new Error(`Connect timeout after ${options.timeout}ms`));
                    }, options.timeout);
                }
            }).on('error', function (e) {
                clearTimeout(connectTimer);
                if (!options.attempts) options.attempts = 1;
                core.info(`Error connecting to ${options.domain} (attempt ${options.attempts}): ${e.message}`);

                if (options.attempts < options.maxRetries) {
                    setTimeout(() => {
                        check(Object.assign({}, options, {
                            attempts: options.attempts + 1,
                        })).then(resolve);
                    }, options.retryDelay);
                } else {
                    core.error(`Error connecting to ${options.domain} after ${options.attempts} attempts`);
                    core.setFailed();
                    resolve();
                }
            })
        });
    }

    for (const domain of MONITOR_DOMAINS.split('|').filter(Boolean)) {
        await check({
            domain,
            hostname: HOST,
            timeout: TIMEOUT,
            errorThreshold: ERROR_THRESHOLD,
            warnThreshold: WARN_THRESHOLD,
            maxRetries: RETRY_ATTEMPTS,
            retryDelay: RETRY_DELAY,
        });
    }

    if (warnings.length && SLACK_WEBHOOK) {
        const res = await fetch(SLACK_WEBHOOK, {
            method:  'POST',
            headers: {'content-type': 'application/json'},
            body:    JSON.stringify({
                blocks: [{
                    type: 'rich_text',
                    elements: [{
                        type: 'rich_text_section',
                        elements: [{
                            type: 'text',
                            text: 'The following certificates expire soon:',
                        }],
                    }, {
                        type: 'rich_text_list',
                        style: 'bullet',
                        elements: warnings.map(({domain, daysLeft, date}) => ({
                            type: 'rich_text_section',
                            elements: [{
                                type: 'text',
                                text: domain + ': ',
                            }, {
                                type: 'text',
                                style: {bold: true},
                                text: daysLeft.toString(),
                            }, {
                                type: 'text',
                                text: ` days (${date})`,
                            }],
                        })),
                    }],
                }],
            }),
        });

        if (!res.ok) {
            core.setFailed('Error with Slack notification: ' + await res.text());
        }
    }
};
