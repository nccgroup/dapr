export const uninstall = async (pid: string): Promise<Response> =>
  await authedFetch(`http://localhost:8888/session/uninstall`, {
    method: "POST",
    body: JSON.stringify({ pid: pid })
  });

export const install = async (pid: number): Promise<Response> =>
  await authedFetch(`http://localhost:8888/session/install`, {
    method: "POST",
    body: JSON.stringify({ pid: pid, adb: false })
  });

export const fetchCurrentProcesses = async (): Promise<any> => {
  const respJSON = await authedFetch(`http://localhost:8888/procs`);
  return await respJSON.json();
};

export const daprTokenName = "dapr";
const auth = async (): Promise<string> => {
  const password = prompt("What's the password");
  const tokenJSON: Response = await jsonFetch("http://localhost:8888/auth", {
    method: "POST",
    body: JSON.stringify({ password: password })
  });
  if (tokenJSON.status === 403) {
    return "";
  }
  const { token }: { token: string } = await tokenJSON.json();
  return token;
};

const getAuthToken = (): string => localStorage.getItem(daprTokenName) || "";
const jsonFetch = async (url: RequestInfo, opts?: RequestInit) => {
  return await fetch(
    url,
    Object.assign({ headers: { "Content-Type": "application/json" } }, opts)
  );
};
const authedFetch = async (
  url: RequestInfo,
  opts?: RequestInit
): Promise<Response> => {
  let token: string;
  while (!(token = getAuthToken())) {
    token = await auth();
    if (!token) {
      continue;
    }
    localStorage.setItem(daprTokenName, token);
    break;
  }
  return await jsonFetch(
    url,
    Object.assign(
      {},
      {
        headers: {
          [daprTokenName]: token
        }
      },
      opts
    )
  );
};
