const sessionForm = document.querySelector("#session");
const workspace = document.querySelector("#workspace");
const message = document.querySelector("#message");
let session = null;

function value(id, next) {
  document.querySelector(`#${id}`).textContent = next ?? "—";
}

async function api(path, options = {}) {
  const response = await fetch(`/api/admin/${encodeURIComponent(session.tenant)}/${path}`, {
    ...options,
    headers: {
      "Authorization": `Bearer ${session.token}`,
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
  });
  const body = await response.json();
  if (!response.ok) throw new Error(body.detail || `Request failed (${response.status})`);
  return body;
}

function applyCapabilities(capabilities) {
  const granted = new Set(capabilities);
  document.querySelectorAll("[data-capability]").forEach((section) => {
    section.hidden = !granted.has(section.dataset.capability);
  });
}

async function openWorkspace(event) {
  event.preventDefault();
  session = {
    tenant: document.querySelector("#tenant").value,
    token: document.querySelector("#token").value,
  };
  try {
    const overview = await api("overview");
    applyCapabilities(overview.capabilities);
    value("coverage", overview.coverage_status);
    value("gaps", overview.gap_count);
    value("unmatched", overview.unmatched_count);
    value("attestations", overview.attestation_count);
    document.querySelector("#identity").textContent = `${overview.subject} · ${session.tenant}`;
    workspace.hidden = false;
    message.textContent = "Workspace loaded.";
  } catch (error) {
    workspace.hidden = true;
    message.textContent = error.message;
  }
}

async function submit(event) {
  event.preventDefault();
  const form = event.currentTarget;
  try {
    const payload = JSON.parse(form.elements.payload.value);
    let path = form.dataset.operation;
    if (form.dataset.lifecycle) {
      const id = encodeURIComponent(form.elements.attestation_id.value);
      path = `attestations/${id}/${form.dataset.lifecycle}`;
    }
    const result = await api(path, {method: "POST", body: JSON.stringify(payload)});
    message.textContent = result.message || "Administrative operation recorded.";
  } catch (error) {
    message.textContent = error.message;
  }
}

sessionForm.addEventListener("submit", openWorkspace);
document.querySelectorAll("main form").forEach((form) => form.addEventListener("submit", submit));
