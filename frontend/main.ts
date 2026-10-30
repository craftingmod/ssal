declare const ksu:
  { exec(command: string, options: string, callback: string): void } | undefined
const button = document.querySelector<HTMLButtonElement>("#restart")!
const status = document.querySelector<HTMLElement>("#status")!

button.addEventListener("click", () => {
  if (typeof ksu === "undefined") {
    status.textContent = "KernelSU WebUI에서 열어 주세요."
    return
  }
  button.disabled = true
  status.textContent = "재시작 중…"
  const callback = `ssalRestart${Date.now()}`
  const callbacks = window as unknown as Record<string, unknown>
  callbacks[callback] = (code: number, stdout: string, stderr: string) => {
    delete callbacks[callback]
    button.disabled = false
    status.textContent =
      code === 0
        ? "ssald가 실행 중입니다."
        : `재시작 실패: ${stderr || stdout || code}`
  }
  try {
    ksu.exec("sh /data/adb/modules/ssal/restart.sh", "{}", callback)
  } catch (error) {
    delete callbacks[callback]
    button.disabled = false
    status.textContent = `실행 실패: ${error}`
  }
})
