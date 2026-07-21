const recordCount = document.querySelector("#recordCount");
const countOutput = document.querySelector("#countOutput");
const equationCount = document.querySelector("#equationCount");
const actualBytes = document.querySelector("#actualBytes");
const encodedBytes = document.querySelector("#encodedBytes");
const capacityLabel = document.querySelector("#capacityLabel");
const writerLabel = document.querySelector("#writerLabel");
const capacityFill = document.querySelector("#capacityFill");
const writerFill = document.querySelector("#writerFill");
const controlNote = document.querySelector("#boundaryHint");
const runButton = document.querySelector("#runExperiment");
const visualStage = document.querySelector("#visualStage");
const stageStatus = document.querySelector("#stageStatus");
const evidenceList = [...document.querySelectorAll("#evidenceList li")];
const evidenceCount = document.querySelector("#evidenceCount");
const verdictBlock = document.querySelector("#verdictBlock");
const consoleLines = document.querySelector("#consoleLines");
const presets = [...document.querySelectorAll(".preset")];
const traceStrip = document.querySelector("#traceStrip");
const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

for (let index = 0; index < 34; index += 1) {
  const tick = document.createElement("i");
  tick.style.setProperty("--i", index);
  traceStrip.append(tick);
}

const format = (value) => new Intl.NumberFormat("en-US").format(value);
const wait = (duration) => new Promise((resolve) => window.setTimeout(resolve, reduceMotion ? 20 : duration));

function getExperiment() {
  const count = Number(recordCount.value);
  const written = count * 16;
  const reserved = written & 0xffff;
  return { count, written, reserved, violation: written > reserved };
}

function setBoundaryPreview() {
  const experiment = getExperiment();
  countOutput.value = format(experiment.count);
  countOutput.textContent = format(experiment.count);
  equationCount.textContent = format(experiment.count);
  actualBytes.textContent = format(experiment.written);
  encodedBytes.textContent = `${format(experiment.reserved)} B`;
  capacityLabel.textContent = `${format(experiment.reserved)} B`;
  writerLabel.textContent = `${format(experiment.written)} B`;

  const scale = Math.max(experiment.written, 65535);
  capacityFill.style.width = `${(experiment.reserved / scale) * 100}%`;
  writerFill.style.width = `${Math.min(100, (experiment.written / scale) * 100)}%`;
  controlNote.textContent = experiment.violation
    ? `The 16-bit body length wraps to ${format(experiment.reserved)} bytes while traversal continues.`
    : experiment.count === 4095
      ? "The list remains representable through 4,095 entries."
      : "The encoded length still matches the bytes the writer will traverse.";

  presets.forEach((button) => {
    button.classList.toggle("is-selected", Number(button.dataset.count) === experiment.count);
  });

  if (!runButton.disabled) {
    visualStage.dataset.verdict = "idle";
    stageStatus.textContent = "Ready";
  }
}

function resetEvidence(running = true) {
  const initialDetails = [
    "bytes_written <= reserved",
    "Exploring the bounded state space",
    "4,095-entry comparison",
    "Fresh ASan build",
    "Evidence not reviewed"
  ];
  evidenceList.forEach((item) => item.classList.remove("is-complete", "is-failure"));
  evidenceList.forEach((item, index) => {
    item.querySelector("span").textContent = initialDetails[index];
  });
  evidenceCount.textContent = "0 / 5";
  verdictBlock.className = "verdict-block";
  verdictBlock.querySelector("strong").textContent = running ? "Running" : "Not run";
  verdictBlock.querySelector("p").textContent = running
    ? "The result remains unclassified while checks are in progress."
    : "Evidence is classified only after formal analysis, replay, control, and review.";
  consoleLines.replaceChildren();
  if (!running) addConsoleLine("Harness ready. Run the boundary replay to classify the evidence.");
}

function addConsoleLine(message, type = "") {
  const line = document.createElement("li");
  line.textContent = message;
  if (type) line.classList.add(type);
  consoleLines.append(line);
}

function completeEvidence(index, detail, failure = false) {
  const item = evidenceList[index];
  item.classList.add("is-complete");
  item.classList.toggle("is-failure", failure);
  item.querySelector("span").textContent = detail;
  evidenceCount.textContent = `${index + 1} / 5`;
}

function setCount(count) {
  recordCount.value = String(count);
  setBoundaryPreview();
}

function animateCount(from, to, duration) {
  return new Promise((resolve) => {
    const startedAt = performance.now();
    const frame = (now) => {
      const progress = Math.min(1, (now - startedAt) / duration);
      const eased = 1 - Math.pow(1 - progress, 3);
      setCount(Math.round(from + ((to - from) * eased)));
      if (progress < 1) {
        requestAnimationFrame(frame);
      } else {
        resolve();
      }
    };
    requestAnimationFrame(frame);
  });
}

function setControlsDisabled(disabled) {
  recordCount.disabled = disabled;
  presets.forEach((button) => { button.disabled = disabled; });
  runButton.disabled = disabled;
}

async function runExperiment() {
  setControlsDisabled(true);
  runButton.disabled = true;
  resetEvidence();
  visualStage.classList.remove("is-running", "is-sweeping");
  void visualStage.offsetWidth;
  visualStage.classList.add("is-sweeping");
  visualStage.dataset.verdict = "safe";
  stageStatus.textContent = "Initializing";
  setCount(0);

  addConsoleLine("[setup] pinned production source and ACK-WRITE-CAPACITY property loaded");
  await wait(560);
  completeEvidence(0, "Capacity contract active");
  addConsoleLine("[formal] bytes_written <= uint16_reserved", "log-pass");
  stageStatus.textContent = "Sweeping";

  await animateCount(0, 3700, 1500);
  await animateCount(3700, 4090, 900);
  for (let count = 4091; count <= 4095; count += 1) {
    setCount(count);
    await wait(300);
  }

  stageStatus.textContent = "Boundary holds";
  addConsoleLine("[control] 4,095 entries -> 65,520 reserved / 65,520 written", "log-pass");
  await wait(850);

  setCount(4096);
  const experiment = getExperiment();
  visualStage.classList.remove("is-sweeping");
  visualStage.classList.add("is-running");
  visualStage.dataset.verdict = "violation";
  stageStatus.textContent = "Violation";
  completeEvidence(1, "Counterexample at serialization loop", true);
  addConsoleLine(`[cbmc] assertion false: ${experiment.written} bytes written into ${experiment.reserved}-byte body`, "log-fail");

  await wait(520);
  completeEvidence(2, "4,095 entries remain clean");

  await wait(520);
  completeEvidence(3, "Heap overflow reproduced under ASan", true);
  addConsoleLine("[replay] AddressSanitizer: heap-buffer-overflow", "log-fail");

  await wait(520);
  completeEvidence(4, "Mechanism accepted; reachability bounded", true);
  addConsoleLine("[critic] witness, control, and production mechanism agree", "log-pass");

  verdictBlock.classList.add("is-failure");
  verdictBlock.querySelector("strong").textContent = "Confirmed violation";
  verdictBlock.querySelector("p").textContent = "Formal counterexample and fresh production replay agree; live-peer reachability remains outside this claim.";
  runButton.querySelector("span:last-child").textContent = "Replay boundary";
  setControlsDisabled(false);
}

recordCount.addEventListener("input", () => {
  resetEvidence(false);
  setBoundaryPreview();
});
presets.forEach((button) => button.addEventListener("click", () => {
  recordCount.value = button.dataset.count;
  resetEvidence(false);
  setBoundaryPreview();
}));
runButton.addEventListener("click", runExperiment);
setBoundaryPreview();

const workflowButton = document.querySelector("#playWorkflow");
const workflowCanvas = document.querySelector("#workflowCanvas");
const phaseLabel = document.querySelector("#phaseLabel");
const phaseCount = document.querySelector("#phaseCount");
const workflowTime = document.querySelector("#workflowTime");
const workflowMessage = document.querySelector("#workflowMessage");
const agents = [...document.querySelectorAll("[data-agent]")];
const paths = [...document.querySelectorAll("[data-path]")];
let workflowRunning = false;
let workflowLooping = false;
let workflowVisible = false;
let workflowToken = 0;

const phases = [
  {
    label: "Coordinator freezes the brief",
    time: "00:01",
    message: "One source pin, one property set, and an unset expected verdict are sealed.",
    active: ["coordinator"], paths: []
  },
  {
    label: "Two framings dispatch",
    time: "00:03",
    message: "Agent 1 hunts a suspected violation. Agent 2 neutrally verifies the same safety boundary.",
    active: ["investigator-a", "investigator-b"], paths: ["dispatch-a", "dispatch-b"]
  },
  {
    label: "Investigators work in isolation",
    time: "18:42",
    message: "Neither investigator can inspect, coach, or react to the other arm before sealing.",
    active: ["investigator-a", "investigator-b"], paths: []
  },
  {
    label: "Hostile review begins",
    time: "27:16",
    message: "Each critic attacks assumptions, model fidelity, controls, and production replay.",
    active: ["critic-a", "critic-b"], paths: ["review-a", "review-b"]
  },
  {
    label: "Coordinator classifies evidence",
    time: "34:08",
    message: "Only now are the sealed arms compared and assigned a conservative final disposition.",
    active: ["synthesis", "coordinator"], paths: ["synthesis"]
  }
];

function resetWorkflow() {
  agents.forEach((agent) => agent.classList.remove("is-active", "is-done"));
  paths.forEach((path) => path.classList.remove("is-active", "is-done"));
  workflowCanvas.dataset.phase = "0";
}

function setWorkflowButton(label) {
  workflowButton.querySelector("span:last-child").textContent = label;
}

function stopWorkflowLoop() {
  workflowLooping = false;
  workflowRunning = false;
  workflowToken += 1;
  setWorkflowButton("Play workflow");
  workflowButton.disabled = false;
}

async function playWorkflow({ loop = false } = {}) {
  if (workflowRunning) return;
  workflowRunning = true;
  workflowLooping = loop && !reduceMotion;
  const token = ++workflowToken;
  workflowButton.disabled = !workflowLooping;
  setWorkflowButton(workflowLooping ? "Pause workflow" : "Playing workflow");

  do {
    resetWorkflow();

    for (let index = 0; index < phases.length; index += 1) {
      if (token !== workflowToken) return;
      const phase = phases[index];
      workflowCanvas.dataset.phase = String(index + 1);
      phaseLabel.textContent = phase.label;
      phaseCount.textContent = `${index + 1} / ${phases.length}`;
      workflowTime.textContent = phase.time;
      workflowMessage.textContent = phase.message;

      agents.forEach((agent) => {
        const active = phase.active.includes(agent.dataset.agent);
        agent.classList.toggle("is-active", active);
      });
      paths.forEach((path) => {
        path.classList.remove("is-active");
        if (phase.paths.includes(path.dataset.path)) path.classList.add("is-active");
      });

      await wait(index === 0 ? 900 : 1350);
      if (token !== workflowToken) return;
      agents.filter((agent) => phase.active.includes(agent.dataset.agent)).forEach((agent) => {
        agent.classList.remove("is-active");
        agent.classList.add("is-done");
      });
      paths.filter((path) => phase.paths.includes(path.dataset.path)).forEach((path) => {
        path.classList.remove("is-active");
        path.classList.add("is-done");
      });
    }

    document.querySelector('[data-agent="synthesis"]').classList.add("is-active");
    if (!workflowLooping || !workflowVisible) break;
    await wait(1800);
  } while (token === workflowToken && workflowLooping && workflowVisible);

  if (token !== workflowToken) return;
  workflowRunning = false;
  workflowLooping = false;
  setWorkflowButton("Replay workflow");
  workflowButton.disabled = false;
}

workflowButton.addEventListener("click", () => {
  if (workflowLooping) {
    stopWorkflowLoop();
    return;
  }
  workflowVisible = true;
  playWorkflow({ loop: !reduceMotion });
});

if (!reduceMotion && "IntersectionObserver" in window) {
  const observer = new IntersectionObserver((entries) => {
    const entry = entries[0];
    workflowVisible = entry.isIntersecting;
    if (workflowVisible && !workflowRunning) {
      playWorkflow({ loop: true });
    } else if (!workflowVisible && workflowLooping) {
      stopWorkflowLoop();
    }
  }, { threshold: .4 });
  observer.observe(document.querySelector("#workflow"));
}
