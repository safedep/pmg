'use strict';

const net = require('node:net');

const proxy = process.env.HTTPS_PROXY || '';
if (proxy === '') {
  console.log('HTTPS_PROXY is empty.');
  process.exit(0);
}
const { hostname, port } = new URL(proxy);
const socket = net.connect({ host: hostname, port: Number(port) }, () => {
  console.log(`HTTPS_PROXY ${proxy} answers.`);
  socket.end();
});
socket.on('error', (err) => {
  console.log(`::error::HTTPS_PROXY names ${proxy}, which does not answer: ${err.message}`);
  process.exitCode = 1;
});
