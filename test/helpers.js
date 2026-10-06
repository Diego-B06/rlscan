import http from 'node:http';
import net from 'node:net';

export function startServer(handler) {
  return new Promise((resolve) => {
    const server = http.createServer(handler);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve({ url: `http://127.0.0.1:${port}`, port, close: () => new Promise((r) => { server.closeAllConnections?.(); server.close(r); }) });
    });
  });
}

/** Servidor TCP que manda cabeceras 200 y deja el cuerpo colgado a medias. */
export function startStallingServer() {
  return new Promise((resolve) => {
    const sockets = new Set();
    const server = net.createServer((sock) => {
      sockets.add(sock);
      sock.on('error', () => {});
      sock.once('data', () => sock.write('HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 100000\r\n\r\n<html>'));
    });
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve({ url: `http://127.0.0.1:${port}`, close: () => new Promise((r) => { sockets.forEach((s) => s.destroy()); server.close(r); }) });
    });
  });
}

const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
export const fakeJwt = (role) => `${b64({ alg: 'HS256', typ: 'JWT' })}.${b64({ iss: 'supabase-demo', role })}.${'f'.repeat(43)}`;

export function send(res, status, body, headers = {}) {
  const buf = Buffer.from(body ?? '');
  res.writeHead(status, { 'Content-Length': buf.length, ...headers });
  res.end(buf);
}
