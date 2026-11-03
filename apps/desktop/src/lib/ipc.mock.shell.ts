// The mock "remote shell": a line editor that echoes input, used by MockTransport sessions.

export interface LineState {
  line: string;
}

/**
 * Feed typed text through the line editor. Returns what the remote echoes back and whether the
 * user typed `exit` (the caller closes the session; nothing after `exit` is processed).
 */
export function echo(s: LineState, text: string): { out: string; exit: boolean } {
  let out = "";
  for (const ch of text) {
    if (ch === "\r") {
      const cmd = s.line.trim();
      s.line = "";
      if (cmd === "exit") return { out: "", exit: true };
      out += `\r\n${cmd ? `${cmd}\r\n` : ""}$ `;
    } else if (ch === "\x7f") {
      if (s.line.length > 0) {
        s.line = s.line.slice(0, -1);
        out += "\b \b";
      }
    } else {
      s.line += ch;
      out += ch;
    }
  }
  return { out, exit: false };
}
