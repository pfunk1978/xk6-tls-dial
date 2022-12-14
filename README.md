# xk6-tls-dial

A tls-wrapped, serialized, tcp api handler with mTLS support.
This plugin only handles tls-wrapped sockets. For clear sockets use the TCP plugin instead.

Usage:
``` javaScript
import tlsdial from 'k6/x/tlsdial';
import { check } from 'k6';
import { Counter } from 'k6/metrics';
import { SharedArray } from 'k6/data';

export const socketDataSent = new Counter('tls_data_sent');
export const socketDataRecv = new Counter('tls_data_received');

// Use a shared array to keep memory down
const conf = new SharedArray('conf', function(){
    let c = Array()
    c[0] = {
        insecure_skip_verify: true, // will validate on SAN, not utilized in this example
        ca_certificates: [
            open('./pki/root.pem'),
            open('./pki/inter.pem'),
            open('./pki/signer.pem')
        ],
        client_certificate: open('./pki/client.pem'),
        client_key: open('./pki/client.skey')
    }
    // add another object as an element if more than one config is to be used
    return c
});

const conn = tlsdial.dial('10.30.16.22:2001', conf[0]); // single connection strictly for API load

export default function () {
    // let conn = tlsdial.dial('10.30.16.22:2001', conf[0]); // connection for every VU to test handshake load
    let message = 'Say Hello';
    tlsdial.writeLn(conn, message);
    socketDataSent.add(message.length);
    let recv = tlsdial.readstring(conn);
    socketDataRecv.add(recv.length);
    check(recv, {
        'said Hello?': (recv) => recv.includes('Hello')
    });
}
```