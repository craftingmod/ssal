export function buildCommand(platform: string, command: string[]) {
  switch (platform) {
    case "win32":
      return ["wslc", "exec", "--workdir", "/src", "ssal-dev", ...command]
    case "linux":
      return command
    default:
      throw new Error(`Unsupported build platform: ${platform}; use Windows with WSLc or Linux`)
  }
}
