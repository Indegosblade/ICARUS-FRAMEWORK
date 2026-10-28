(() => {
  'use strict';
  const token = new URLSearchParams(location.hash.slice(1)).get('token') || '';
  history.replaceState(null, '', location.pathname);
  const $ = id => document.getElementById(id);
  const labels = {files:'path',binaries:'executable_name',daemons:'label',mach_services:'service_name',entitlements:'key',sandbox_profiles:'name',sandbox_rules:'operation',kexts:'bundle_id',frameworks:'path',observations:'event_type',versions:'run_id',atoms:'source_key',bags:'canonical_key',resolution_event_log:'event_type',match_candidates:'entity_type'};
  const provenanceKeys = ['source_version_id','version_id','observed_time','observed_at','confidence','marking'];
  let summary, current = 'files', after = 0, nextAfter = null, previous = [], query = '', requestNumber = 0, detailNumber = 0;

  function node(tag, text, className) {
    const element = document.createElement(tag);
    if (text !== undefined) element.textContent = text;
    if (className) element.className = className;
    return element;
  }
  function display(value) { return value === null || value === undefined ? '—' : String(value); }
  function title(value) { return value.replaceAll('_', ' '); }
  function error(message) { $('error').textContent = message; $('error').hidden = false; }
  async function api(path, params = {}) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 6000);
    try {
      const response = await fetch(path + '?' + new URLSearchParams(params), {
        headers: {Authorization:'Bearer ' + token}, cache:'no-store', credentials:'omit',
        mode:'same-origin', redirect:'error', signal:controller.signal
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Inspection request failed');
      return data;
    } finally { clearTimeout(timeout); }
  }
  function resetInspector() {
    detailNumber++;
    $('detail-title').textContent = 'Select an entity';
    $('detail-subtitle').textContent = 'Open a row to inspect its properties, provenance, and recorded relationships.';
    ['provenance-section','properties-section','relationships-section'].forEach(id => $(id).hidden = true);
  }
  function selectCollection(table) {
    current = table; after = 0; nextAfter = null; previous = []; query = '';
    $('search').value = '';
    resetInspector();
    document.querySelectorAll('.collection').forEach(button => button.classList.toggle('active', button.dataset.table === table));
    $('collection-title').textContent = title(table);
    $('collection-count').textContent = summary.tables[table].toLocaleString() + ' recorded rows';
    const searchable = summary.fts_tables.includes(table);
    $('search').disabled = !searchable; $('search-button').disabled = !searchable;
    $('search-kind').textContent = searchable ? 'FTS5 INDEXED' : 'STRUCTURED RECORDS';
    $('search-help').textContent = searchable ? 'Full-text query · Enter a term or an FTS5 phrase. Results are ordered by object ID.' : 'Full-text search is available in files, daemons, and atoms.';
    loadEntities();
  }
  async function loadEntities() {
    const sequence = ++requestNumber;
    const table = current;
    document.body.setAttribute('aria-busy', 'true');
    $('previous').disabled = true; $('next').disabled = true; $('error').hidden = true;
    try {
      const data = await api('/api/entities', {table, after:String(after), ...(query ? {q:query} : {})});
      if (sequence !== requestNumber) return;
      nextAfter = data.next_after;
      const preferred = ['id',labels[table], table === 'files' ? 'file_type' : 'source_version_id', 'marking'];
      const columns = [...new Set(preferred)].filter(column => data.columns.includes(column));
      const head = node('tr');
      columns.forEach(column => head.append(node('th', title(column))));
      $('entities').querySelector('thead').replaceChildren(head);
      const body = document.createDocumentFragment();
      data.rows.forEach(row => {
        const tr = node('tr');
        columns.forEach(column => {
          const td = node('td');
          let text = display(row[column]);
          if (text.length > 100) text = text.slice(0,100) + '…';
          if (column === labels[table] || column === 'id') {
            const button = node('button', text); button.type = 'button';
            button.addEventListener('click', () => inspect(table, row.id)); td.append(button);
          } else td.textContent = text;
          tr.append(td);
        });
        body.append(tr);
      });
      $('entities').querySelector('tbody').replaceChildren(body);
      $('empty').hidden = data.rows.length > 0;
      $('page-status').textContent = data.rows.length + ' objects on this page' + (query ? ' · filtered' : '') + ' · values capped at ' + data.cells_truncated_at + ' characters';
      $('previous').disabled = previous.length === 0; $('next').disabled = nextAfter === null;
    } catch (failure) { if (sequence === requestNumber) error(failure.message); }
    finally { if (sequence === requestNumber) document.body.setAttribute('aria-busy', 'false'); }
  }
  function properties(target, entries, truncated) {
    const fragment = document.createDocumentFragment();
    entries.forEach(([key,value]) => {
      fragment.append(node('dt', key));
      fragment.append(node('dd', display(value) + (truncated.includes(key) ? ' [preview truncated]' : '')));
    });
    target.replaceChildren(fragment);
  }
  async function inspect(table, id) {
    const sequence = ++detailNumber;
    $('detail-title').textContent = 'Loading entity…';
    try {
      const data = await api('/api/entity', {table, id:String(id)});
      if (sequence !== detailNumber) return;
      const entity = data.entity, truncated = entity._truncated_fields || [];
      $('detail-title').textContent = display(entity[labels[table]] || table + ' #' + id);
      $('detail-subtitle').textContent = table + ' · object #' + id;
      const entries = Object.entries(entity).filter(([key]) => key !== '_truncated_fields');
      properties($('provenance'), entries.filter(([key]) => provenanceKeys.includes(key)), truncated);
      properties($('properties'), entries.filter(([key]) => !provenanceKeys.includes(key)), truncated);
      $('provenance-section').hidden = !entries.some(([key]) => provenanceKeys.includes(key));
      $('properties-section').hidden = false; $('relationships-section').hidden = false;
      const groups = document.createDocumentFragment();
      data.relationships.forEach(relation => {
        const group = node('div', undefined, 'relation-group');
        group.append(node('div', relation.title, 'relation-label'));
        relation.items.forEach(item => {
          const button = node('button', display(item.label || relation.table + ' #' + item.id), 'relation-link');
          button.type = 'button'; button.addEventListener('click', () => inspect(relation.table, item.id));
          group.append(button);
        });
        if (relation.truncated) group.append(node('p', 'Showing the first 10 related objects.', 'relation-note'));
        groups.append(group);
      });
      if (!data.relationships.length) groups.append(node('p', 'No recorded relationships for this object.', 'muted'));
      if (data.relationships.length >= data.relationship_group_limit) groups.append(node('p', 'Relationship group limit reached; this is a bounded preview.', 'relation-note'));
      $('relationships').replaceChildren(groups);
    } catch (failure) { if (sequence === detailNumber) error(failure.message); }
  }
  $('search-form').addEventListener('submit', event => {
    event.preventDefault(); query = $('search').value.trim(); after = 0; previous = []; loadEntities();
  });
  $('clear-search').addEventListener('click', () => {
    $('search').value = ''; query = ''; after = 0; previous = []; loadEntities();
  });
  $('next').addEventListener('click', () => { if (nextAfter !== null) { previous.push(after); after = nextAfter; loadEntities(); } });
  $('previous').addEventListener('click', () => { if (previous.length) { after = previous.pop(); loadEntities(); } });
  async function start() {
    if (!/^[A-Za-z0-9_-]{43}$/.test(token)) { error('Open the complete session URL printed by icarus gui in your terminal.'); return; }
    try {
      summary = await api('/api/summary'); $('database-name').textContent = summary.database;
      if (summary.sanitization !== 'verified') {
        $('warning').textContent = 'Sanitization: ' + summary.sanitization + '. This database may contain private data. Read-only access protects the file; it does not sanitize what you view.';
        $('warning').hidden = false;
      }
      for (const [table,count] of Object.entries(summary.tables)) {
        const button = node('button', undefined, 'collection'); button.type = 'button'; button.dataset.table = table;
        button.append(node('span', title(table)), node('span', count.toLocaleString(), 'collection-count'));
        button.addEventListener('click', () => selectCollection(table)); $('collections').append(button);
      }
      selectCollection('files');
    } catch (failure) { error(failure.message); }
  }
  start();
})();
