const colors = {
  // Standard colors
  black: "\x1b[30m",
  red: "\x1b[31m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  blue: "\x1b[34m",
  magenta: "\x1b[35m",
  cyan: "\x1b[36m",
  white: "\x1b[37m",

  // Bright colors
  brightBlack: "\x1b[90m",
  brightRed: "\x1b[91m",
  brightGreen: "\x1b[92m",
  brightYellow: "\x1b[93m",
  brightBlue: "\x1b[94m",
  brightMagenta: "\x1b[95m",
  brightCyan: "\x1b[96m",
  brightWhite: "\x1b[97m",

  // Background colors
  bgBlack: "\x1b[40m",
  bgRed: "\x1b[41m",
  bgGreen: "\x1b[42m",
  bgYellow: "\x1b[43m",
  bgBlue: "\x1b[44m",
  bgMagenta: "\x1b[45m",
  bgCyan: "\x1b[46m",
  bgWhite: "\x1b[47m",

  // Bright background colors
  bgBrightBlack: "\x1b[100m",
  bgBrightRed: "\x1b[101m",
  bgBrightGreen: "\x1b[102m",
  bgBrightYellow: "\x1b[103m",
  bgBrightBlue: "\x1b[104m",
  bgBrightMagenta: "\x1b[105m",
  bgBrightCyan: "\x1b[106m",
  bgBrightWhite: "\x1b[107m",

  // Text styles
  bold: "\x1b[1m",
  dim: "\x1b[2m",
  italic: "\x1b[3m",
  underline: "\x1b[4m",
  blink: "\x1b[5m",
  inverse: "\x1b[7m",
  hidden: "\x1b[8m",
  strikethrough: "\x1b[9m",

  // Reset all attributes
  reset: "\x1b[0m",
};

function init() {
  let members = {};

  fetch("/reset-console/assets/members.json")
    .then((res) => {
      if (!res.ok) throw new Error("Failed to load members.json");
      return res.json();
    })
    .then((data) => {
      members = data.members;
      console.log("Loaded members:", members);
    })
    .catch((err) => {
      console.error("Error loading members.json:", err);
    });

  const term = new Terminal({
    cursorBlink: true,
    theme: {
      background: "#040404",
      foreground: "#f5f5f5",
    },
  });

  const fitAddon = new FitAddon.FitAddon();
  const webLinksAddon = new WebLinksAddon.WebLinksAddon();
  term.loadAddon(fitAddon);
  term.loadAddon(webLinksAddon);

  term.open(document.getElementById("terminal"));
  fitAddon.fit();

  const env = {};
  const aliases = {};
  let commandBuffer = "";
  const commandHistory = [];
  let historyIndex = -1;

  let welcomemessage = `${colors.brightGreen}guest@resetsec${colors.reset}:~$ `;

  term.writeln(`Welcome to ${colors.brightRed}Reset Security${colors.reset}.`);
  term.writeln(`Run [${colors.blue}help${colors.reset}] to get started.`);
  term.write(`${welcomemessage}`);

  term.onKey(({ key, domEvent }) => {
    const char = key;
    const code = domEvent.key;

    if (code === "Enter") {
      term.writeln("");
      if (commandBuffer.trim() !== "") {
        commandHistory.unshift(commandBuffer);
        historyIndex = -1;
      }
      handleCommand(commandBuffer.trim());
      commandBuffer = "";
      term.write(`\r\n${welcomemessage}`);
    } else if (code === "Backspace") {
      if (commandBuffer.length > 0) {
        commandBuffer = commandBuffer.slice(0, -1);
        term.write("\b \b");
      }
    } else if (code === "ArrowUp") {
      if (
        commandHistory.length > 0 &&
        historyIndex < commandHistory.length - 1
      ) {
        historyIndex++;
        replaceInput(commandHistory[historyIndex]);
      }
    } else if (code === "ArrowDown") {
      console.log("down");
      if (historyIndex > 0) {
        historyIndex--;
        replaceInput(commandHistory[historyIndex]);
      } else {
        historyIndex = -1;
        replaceInput("");
      }
    } else if (code.length === 1 || char.length === 1) {
      commandBuffer += char;
      term.write(char);
    }
  });

  window.addEventListener("resize", () => {
    fitAddon.fit();
  });
  function resolveAliases(cmd) {
    const [base, ...args] = cmd.trim().split(/\s+/);
    return aliases[base] ? `${aliases[base]} ${args.join(" ")}` : cmd;
  }
  function replaceInput(newInput) {
    while (commandBuffer.length > 0) {
      term.write("\b \b");
      commandBuffer = commandBuffer.slice(0, -1);
    }

    commandBuffer = newInput;
    term.write(commandBuffer);
  }
  function handleCommand(rawInput) {
    const cmd = resolveAliases(rawInput.trim());
    const [base, ...args] = cmd.split(/\s+/);
    switch (base) {
      case "help":
        term.writeln("");
        term.writeln("Available commands:");
        term.writeln("");
        term.writeln("  Command        Description");
        term.writeln("  -------        -----------");
        term.writeln("  help           Display this help message");
        term.writeln("  switch         Switch back to the other website");
        term.writeln("  about          Information about RESETSEC");
        term.writeln("  writeups       Show links to challenge writeups");
        term.writeln("  whoami         Show your current user");
        term.writeln(
          "  echo [args]    Print arguments to stdout (supports $VARS)",
        );
        term.writeln("  env            List environment variables");
        term.writeln("  export VAR=val Set environment variable");
        term.writeln("  alias [a=b]    List or define command aliases");
        term.writeln("  unalias a      Remove a previously defined alias");
        term.writeln(
          "  cat [file]     Concatenate file(s) to stdout (e.g., cat members)",
        );
        term.writeln("  reset          Reset the terminal");
        term.writeln("  cls            Clear the screen");
        term.writeln(
          "  exit           Close the terminal (may be blocked by browser)",
        );
        term.writeln("");
        term.writeln("Hint: Try `export USER=admin` followed by `echo $USER`.");
        term.writeln("");
        break;
      case "about":
        term.writeln(
          "We are a CTF Team created by some nerds on Reddit that hopped into\r\na discord together and instantly became a big, weird, international\r\nfamily :P (no, we don’t know how it happened)",
        );
        break;
      case "switch":
        term.writeln("Switching to main site...");
        setTimeout(() => {
          window.location.href = "/";
        }, 500);
        break;
      case "writeups":
        term.writeln("Available writeups:");
        term.writeln("- https://resetsec.github.io/writeups/NONE");
        break;
      case "whoami":
        term.writeln("guest");
        break;
      case "alias":
        if (args.length === 0) {
          for (let a in aliases) term.writeln(`alias ${a}='${aliases[a]}'`);
        } else {
          const [name, value] = args.join(" ").split("=");
          if (name && value) aliases[name] = value.replace(/^['"]|['"]$/g, "");
        }
        break;

      case "unalias":
        delete aliases[args[0]];
        break;

      case "export":
        const [varName, varValue] = args.join(" ").split("=");
        if (varName && varValue !== undefined) env[varName] = varValue;
        break;

      case "env":
        for (let k in env) term.writeln(`${k}=${env[k]}`);
        break;

      case "echo":
        const expanded = args
          .map((arg) => (arg.startsWith("$") ? (env[arg.slice(1)] ?? "") : arg))
          .join(" ");
        term.writeln(expanded);
        break;
      case "cat":
        if (!args[0]) {
          term.writeln("cat: missing operand");
        } else if (args[0] === "members" || args[0] === "/etc/passwd") {
          Object.keys(members).forEach((member) => {
            term.writeln(`${member}:x:1000:1000::/home/${member}:/bin/bash`);
          });
        } else {
          term.writeln(`cat: ${args[0]}: No such file or directory`);
        }
        break;
      case "exit":
        window.close();
        break;
      case "reset":
        term.reset();
        break;
      case "cls":
        term.clear();
        break;
      default:
        term.writeln(`Unknown command: ${cmd}`);
    }
  }
  term.focus();

  const loader = document.querySelector(".loader");
  loader.style.animation = "loader-blink 750ms forwards";
  loader.style.animationDelay = "100ms";
}

window.addEventListener("load", init);
