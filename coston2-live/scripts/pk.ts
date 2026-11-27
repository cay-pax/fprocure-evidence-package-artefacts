// Test passkeys that survive restarts: P-256 keys kept as JWK (local test data only).
import { ethers } from "npm:ethers@6.16.0";
import { normaliseS, passkeyId } from "/home/ubuntu/wt-e2e/supabase/functions/_lib/passkey.ts";
const b64url = (b: Uint8Array) => btoa(String.fromCharCode(...b)).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
export interface Pk { qx: string; qy: string; keyId: string; jwk: JsonWebKey; sign(c: string): Promise<Record<string, unknown>> }
export async function newPk(): Promise<Pk> {
  const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  return loadPk(await crypto.subtle.exportKey("jwk", kp.privateKey));
}
export async function loadPk(jwk: JsonWebKey): Promise<Pk> {
  const key = await crypto.subtle.importKey("jwk", jwk, { name: "ECDSA", namedCurve: "P-256" }, true, ["sign"]);
  const dec = (s: string) => Uint8Array.from(atob(s.replaceAll("-", "+").replaceAll("_", "/")), (c) => c.charCodeAt(0));
  const qx = ethers.hexlify(dec(jwk.x!)), qy = ethers.hexlify(dec(jwk.y!));
  return {
    qx, qy, keyId: passkeyId(qx, qy), jwk,
    async sign(challenge: string) {
      const authData = new Uint8Array(37); authData[32] = 0x05;
      const clientDataJSON = JSON.stringify({ type: "webauthn.get", challenge: b64url(ethers.getBytes(challenge)), origin: "https://fprocure.example" });
      const clientHash = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(clientDataJSON)));
      const sig = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, ethers.getBytes(ethers.concat([authData, clientHash]))));
      return { r: ethers.hexlify(sig.slice(0, 32)), s: normaliseS(ethers.hexlify(sig.slice(32))), challengeIndex: clientDataJSON.indexOf('"challenge"'), typeIndex: clientDataJSON.indexOf('"type"'), authenticatorData: ethers.hexlify(authData), clientDataJSON };
    },
  };
}
