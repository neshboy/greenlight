import http, { IncomingMessage, ServerResponse } from "node:http";
import tls from "node:tls";
import net from "node:net";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export interface RunningHttpServer {
  server: http.Server;
  port: number;
  url: string;
  close: () => Promise<void>;
}

/** Starts a real HTTP server on loopback with the given request handler. */
export function startHttpServer(
  handler: (req: IncomingMessage, res: ServerResponse) => void
): Promise<RunningHttpServer> {
  return new Promise((resolve, reject) => {
    const server = http.createServer(handler);
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      if (!addr || typeof addr === "string") {
        reject(new Error("failed to bind test server"));
        return;
      }
      const port = addr.port;
      resolve({
        server,
        port,
        url: `http://127.0.0.1:${port}`,
        close: () => new Promise((res) => server.close(() => res())),
      });
    });
  });
}

export interface RunningTlsServer {
  server: tls.Server;
  port: number;
  close: () => Promise<void>;
}

const VALID_CERT = fs.readFileSync(path.join(__dirname, "valid-cert.pem"));
const VALID_KEY = fs.readFileSync(path.join(__dirname, "valid-key.pem"));
const EXPIRING_CERT = fs.readFileSync(path.join(__dirname, "expiring-cert.pem"));
const EXPIRING_KEY = fs.readFileSync(path.join(__dirname, "expiring-key.pem"));

export { VALID_CERT, VALID_KEY, EXPIRING_CERT, EXPIRING_KEY };

/** Starts a real TLS server on loopback using the given cert/key pair. */
export function startTlsServer(cert: Buffer, key: Buffer): Promise<RunningTlsServer> {
  return new Promise((resolve, reject) => {
    const server = tls.createServer({ cert, key }, (socket) => {
      socket.end();
    });
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      if (!addr || typeof addr === "string") {
        reject(new Error("failed to bind TLS test server"));
        return;
      }
      resolve({
        server,
        port: addr.port,
        close: () => new Promise((res) => server.close(() => res())),
      });
    });
  });
}

export interface RunningTcpServer {
  server: net.Server;
  port: number;
  close: () => Promise<void>;
}

/** Starts a bare TCP listener (accepts and immediately holds connections open) — used to simulate an "open" port. */
export function startTcpServer(): Promise<RunningTcpServer> {
  return new Promise((resolve, reject) => {
    const server = net.createServer((socket) => {
      socket.on("error", () => {});
    });
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      if (!addr || typeof addr === "string") {
        reject(new Error("failed to bind TCP test server"));
        return;
      }
      resolve({
        server,
        port: addr.port,
        close: () => new Promise((res) => server.close(() => res())),
      });
    });
  });
}

/** Finds a loopback TCP port that is guaranteed to be closed (nothing listening), for "closed port" test cases. */
export async function findClosedPort(): Promise<number> {
  const tmp = await startTcpServer();
  const port = tmp.port;
  await tmp.close();
  return port;
}
