var helmet = require('helmet');
import bodyParser from 'body-parser';
import express from 'express';
import http from 'http';
import https from 'https';
import fs from 'fs';
import _ from 'underscore';
import shell from 'shelljs';
import gammaConfig from './config';
import * as db from './db';
import constants from 'constants';
import * as cf from './../utils/common-functions';
import * as log from './../logs/logger';
import passport from 'passport';
import {
    getIsAliveStatus
} from './../api/v2/repository/scans/scan.controller';

import {
    setEmboldSecurityCheck
} from './../api/v1/repository/codeCheckers/codeCheckers.controller';
import * as cors from './cors';

var app = express();
var publicDir = "/public";
if (process.env.NODE_ENV == 'production')
    publicDir = "/dist";
http.globalAgent.maxSockets = 20;


function init() {
    // Avoids DEPTH_ZERO_SELF_SIGNED_CERT error
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
    //Promise.promisifyAll(require('async'));
    if (!shell.which('bash')) {
        log.error(`Sorry, this application requires bash.Please add 'bash' to PATH variable.`);
        shell.exit(1);
    }

    if (process.env.GAMMA_ACCOUNT && process.getuid) {
        try {
            process.setuid(process.env.GAMMA_ACCOUNT);
        } catch (err) {
            log.warn(`Failed to set user: ${err}`);
        }
    }
    app.set('port', gammaConfig.port);

    // for parsing application/json
    app.use(bodyParser.json({
        limit: '10mb'
    }));

    // for parsing application/xwww-
    app.use(bodyParser.urlencoded({
        extended: true,
        limit: '10mb',
        parameterLimit: 50000
    }));
    app.use(helmet());

    app.use(cors.sanitize);

    //if (_.contains(["true", true], gammaConfig.is_cloud)) {
    app.use(cors.applyCors(app));
    //}

    require('./passport/passport')(app, passport);
    app.use(passport.initialize());

    require('./master-routes')(app);

    startServer();
    createUploadDirectory();
    initAnalysisService();
    //setEmboldSecurityCheck();
}

function startServer() {
    try {
        if (gammaConfig.clusterEnabled && cluster.isMaster) {
            var numCPUs = require('os').cpus().length;

            for (var i = 0; i < numCPUs; i++) {
                cluster.fork();
            }
            Object.keys(cluster.workers).forEach(function (id) {
                log.print(log.level.DEBUG, cluster.workers[id].process.pid);
            });

            cluster.on('exit', function (worker, code, signal) {
                log.warn(`worker ${worker.process.pid} died`);
            });
        } else {
            var server = http.createServer(app);
            server.listen(app.get('port'), '0.0.0.0', function (server1) {
                let productVersion = gammaConfig.version;
                if (gammaConfig.productVersion) {
                    productVersion = gammaConfig.productVersion
                } else {
                    log.info("UI version set as Product version");
                }

                log.info(`Embold server (Product Version-${productVersion}) (UI Version-${gammaConfig.version}) listening on port ${app.get('port')}`);
            });
            var io = require('socket.io')();
            io.attach(server);

            var keyPath = cf.actualPath(gammaConfig.ssl.key);
            var certPath = cf.actualPath(gammaConfig.ssl.cert);
            fs.exists(certPath, function (exists) {
                if (exists) {
                    var options = {
                        key: fs.readFileSync(keyPath),
                        cert: fs.readFileSync(certPath),
                        passphrase: gammaConfig.ssl.passphrase
                    };
                    //if (_.contains(["true", true], gammaConfig.is_cloud)) {
                    options.secureOptions = constants.SSL_OP_NO_SSLv2 | constants.SSL_OP_NO_SSLv3 | constants.SSL_OP_NO_TLSv1 | constants.SSL_OP_NO_TLSv1_1
                    //}
                    var httpsServer = https.createServer(options, app)

                    httpsServer.listen(gammaConfig.ssl.port, function (server1) {
                        log.info(`Express (https) server listening on port ${gammaConfig.ssl.port}`);
                    });
                    io.attach(httpsServer);
                } else {
                    log.warn(`SSL certificate does not exist`);
                }
            });

            module.exports.socket = require('./../sockets/socket').init(io);

            //creating gamma db connection pool
            db.initGammaDB();

            //setup email config
            require('./../core/email').setEmailConfig();
        }
    } catch (err) {
        log.error(err);
    }
}

function createUploadDirectory() {
    const UPLOADS_DIR = `.${publicDir}/uploads`;
    // Create uploads directory if not exist
    if (!fs.existsSync(UPLOADS_DIR)) {
        if (_.contains(["true", true], gammaConfig.is_cloud)) {
            console.log("Cloud :: Upload directory does not exist :: Creating new with 744 permission");
            // Below log.debug is not working in production using binary app
            // log.debug("Cloud :: Upload directory does not exist :: Creating new with 744 permission");
            try {
                fs.mkdirSync(UPLOADS_DIR, {
                    recursive: true,
                    mode: 0o744
                })
            } catch (err) {
                if (err.code !== 'EEXIST')
                    console.log(err);
            }
        } else {
            console.log("OnPremise :: Upload directory does not exist :: Creating new with 770 permission");
            // Below log.debug is not working in production using binary app
            // log.debug("OnPremise :: Upload directory does not exist :: Creating new with 770 permission");
            try {
                fs.mkdirSync(UPLOADS_DIR, {
                    recursive: true,
                    mode: 0o770
                })
            } catch (err) {
                if (err.code !== 'EEXIST')
                    console.log(err);
            }
        }
    }
}

function initAnalysisService() {
    let get_analysis_status = setInterval(function () {
        getIsAliveStatus();
        // if (_.contains(["true", true], gammaConfig.enablePRScan) && gammaConfig.polling_pr_cron_time && gammaConfig.polling_pr_cron_time != "") {
        //     getIsPRAliveStatus();
        // }
    }, 30000);
}

process.on('SIGINT', function () {
    log.warn(`Cleaning node data before exit`);
    log.shutDownLogger();
});

process.on('uncaughtException', function (err) {
    log.fatal(`${(new Date).toUTCString()} uncaughtException: ${err.message}`);
    log.error(err.stack);
});

/* process.on('unhandledRejection', error => {
    // Won't execute
    log.debug(error);
}); */

module.exports.beta = "7279546f";
module.exports.alpha = "70536563";
module.exports.init = init;
module.exports.publicDir = publicDir;
module.exports.emptyPromise = new Promise(function (resolve, reject) {
    resolve([])
});
module.exports.i18next = require('../core/i18next')(app);
module.exports.deletedRepositories = {};
export default app;