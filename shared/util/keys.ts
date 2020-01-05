import { shell } from "./procs";
import { existsSync } from "fs";

export const pubKey = "./config/public.pem";
export const privKey = "./config/private.pem";
export const genJWTKeys = (): void => {
  if (keysGenerated()) {
    return;
  }
  shell(`openssl genrsa -out ${privKey} 2048`.split(" "), false);
  shell(`openssl rsa -in ${privKey} -pubout -out ${pubKey}`.split(" "), false);
};
const keysGenerated = (): boolean => {
  try {
    if (existsSync(pubKey) && existsSync(privKey)) {
      return true;
    }
  } catch (err) {
    return false;
  }

  return false;
};
