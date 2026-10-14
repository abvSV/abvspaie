(() => {
  function toast(message, state) {
    const notification = document.createElement("div");
    notification.className = "toast";
    notification.dataset.state = state || "info";
    notification.setAttribute("role", state === "error" ? "alert" : "status");
    notification.setAttribute("aria-live", state === "error" ? "assertive" : "polite");
    notification.textContent = message;
    document.body.appendChild(notification);
    window.setTimeout(() => notification.remove(), 3600);
  }

  window.toast = toast;

  document.addEventListener("click", event => {
    const copyButton = event.target.closest("[data-copy]");
    if (copyButton) {
      if (!navigator.clipboard || !navigator.clipboard.writeText) {
        toast("La copie n'est pas disponible dans ce navigateur. Copiez le lien manuellement.", "error");
        return;
      }
      Promise.resolve().then(() => navigator.clipboard.writeText(copyButton.dataset.copy)).then(
        () => toast("Lien copié."),
        () => toast("Copie refusée par le navigateur. Copiez le lien manuellement.", "error")
      );
      return;
    }

    const messageButton = event.target.closest("[data-toast]");
    if (messageButton) toast(messageButton.dataset.toast);
  });

  function filterRows(event) {
    const control = event.target.closest("[data-filter]");
    if (!control) return;

    const tableId = control.dataset.filter;
    const table = document.getElementById(tableId);
    if (!table) return;
    const card = table.closest(".card");
    const query = (card?.querySelector('input[data-filter="' + tableId + '"]')?.value || "").trim().toLocaleLowerCase("fr");
    const status = card?.querySelector('select[data-filter="' + tableId + '"]')?.value || "";
    const rows = [...table.querySelectorAll("tbody tr")].filter(row => row.dataset.s);
    const messageRows = [...table.querySelectorAll("tbody tr")].filter(row => !row.dataset.s && !row.dataset.filterEmpty);
    const hasFilter = Boolean(query || status);
    messageRows.forEach(row => { row.hidden = hasFilter; });
    let visibleRows = 0;
    rows.forEach(row => {
      row.hidden = !row.textContent.toLocaleLowerCase("fr").includes(query) || Boolean(status && row.dataset.s !== status);
      if (!row.hidden) visibleRows++;
    });
    let emptyRow = table.querySelector("tbody tr[data-filter-empty]");
    if (hasFilter && visibleRows === 0) {
      if (!emptyRow) {
        emptyRow = document.createElement("tr");
        emptyRow.dataset.filterEmpty = "";
        const cell = document.createElement("td");
        cell.colSpan = table.querySelectorAll("thead th").length || 1;
        emptyRow.appendChild(cell);
        table.querySelector("tbody").appendChild(emptyRow);
      }
      emptyRow.firstElementChild.textContent = "Aucun résultat ne correspond à ces filtres.";
      emptyRow.hidden = false;
    } else if (emptyRow) {
      emptyRow.remove();
    }
  }

  document.addEventListener("input", filterRows);
  document.addEventListener("change", filterRows);
})();
