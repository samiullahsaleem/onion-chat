'use strict';
// Onion Chat client. All encryption happens here: each chat runs an ephemeral
// ECDH P-256 exchange, derives an AES-256-GCM key with HKDF, and only
// ciphertext ever reaches the server. Keys live in memory and are
// non-extractable; closing the tab destroys them.
(() => {
  const $ = id => document.getElementById(id);
  const enc = new TextEncoder();
  const dec = new TextDecoder();
  const ECDH = { name: 'ECDH', namedCurve: 'P-256' };
  const MAX_LEN = 4000;
  const MAX_HISTORY = 500;

  let me = '';
  let token = '';
  let es = null;
  let leaving = false;
  let online = [];
  let current = null;           // peer name of the open chat
  let inbox = Promise.resolve(); // relayed events are handled one at a time, in order
  let outbox = Promise.resolve(); // so are sends, which keeps sequence numbers ordered
  let lastTyping = 0;
  const chats = new Map();      // peer name -> chat
  const blocked = new Set();

  // ---------- small helpers

  function el(tag, cls, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  }

  const b64e = buf => {
    let s = '';
    for (const b of new Uint8Array(buf)) s += String.fromCharCode(b);
    return btoa(s);
  };
  const b64d = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
  const clock = () => new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

  let toastTimer = 0;
  function toast(text) {
    const t = $('toast');
    t.textContent = text;
    t.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { t.hidden = true; }, 4000);
  }

  async function api(path, body) {
    const headers = { 'Content-Type': 'application/json' };
    if (token) headers.Authorization = 'Bearer ' + token;
    const res = await fetch('/api/' + path, {
      method: 'POST', headers, cache: 'no-store', body: JSON.stringify(body || {}),
    });
    if (!res.ok) {
      const err = new Error((await res.text()).trim() || res.statusText);
      err.status = res.status;
      throw err;
    }
    return res.status === 204 ? null : res.json();
  }

  const relay = (to, type, data) => api('send', { to, type, data });

  // ---------- crypto

  async function newKeys() {
    const kp = await crypto.subtle.generateKey(ECDH, false, ['deriveBits']);
    const pub = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey));
    return { priv: kp.privateKey, pub };
  }

  function compare(a, b) {
    for (let i = 0; i < Math.min(a.length, b.length); i++) if (a[i] !== b[i]) return a[i] - b[i];
    return a.length - b.length;
  }

  // Derives the chat key from our private key and the peer's public key. The
  // safety code is a hash of both public keys: if the server swapped keys in
  // the middle, the two sides would see different codes.
  async function establish(c, peerPubB64) {
    const peerPub = b64d(peerPubB64);
    const peerKey = await crypto.subtle.importKey('raw', peerPub, ECDH, false, []);
    const bits = await crypto.subtle.deriveBits({ name: 'ECDH', public: peerKey }, c.keys.priv, 256);
    const [x, y] = compare(c.keys.pub, peerPub) < 0 ? [c.keys.pub, peerPub] : [peerPub, c.keys.pub];
    const both = new Uint8Array(x.length + y.length);
    both.set(x);
    both.set(y, x.length);
    const salt = new Uint8Array(await crypto.subtle.digest('SHA-256', both));
    const ikm = await crypto.subtle.importKey('raw', bits, 'HKDF', false, ['deriveKey']);
    c.key = await crypto.subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt, info: enc.encode('onion-chat/v1') },
      ikm, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    c.safety = safetyCode(salt);
    c.keys = null; // the private key is no longer needed; dropping it gives forward secrecy
    c.sendSeq = 0;
    c.recvSeq = 0;
    c.state = 'active';
  }

  function safetyCode(hash) {
    const groups = [];
    for (let i = 0; i < 30; i += 5) {
      let n = 0;
      for (let j = 0; j < 5; j++) n = n * 256 + hash[i + j];
      groups.push(String(n % 100000).padStart(5, '0'));
    }
    return groups.join(' ');
  }

  // Names are bound into the associated data so a message can't be reflected
  // back to its sender or redirected to someone else.
  async function seal(c, obj) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData: enc.encode(me + '\n' + c.peer) },
      c.key, enc.encode(JSON.stringify(obj)));
    return { iv: b64e(iv), ct: b64e(ct) };
  }

  async function unseal(c, d) {
    const pt = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: b64d(d.iv), additionalData: enc.encode(c.peer + '\n' + me) },
      c.key, b64d(d.ct));
    return JSON.parse(dec.decode(pt));
  }

  // ---------- chat state

  // States: 'out' (we asked), 'in' (they asked), 'active', 'ended'.
  function resetChat(peer, state) {
    let c = chats.get(peer);
    if (!c) {
      c = { peer, msgs: [], unread: 0 };
      chats.set(peer, c);
    }
    Object.assign(c, { state, keys: null, key: null, peerPub: null, safety: null, typingUntil: 0 });
    return c;
  }

  function push(c, who, text) {
    c.msgs.push({ who, text, time: clock() });
    if (c.msgs.length > MAX_HISTORY) c.msgs.shift();
  }

  const note = (c, text) => push(c, 'sys', text);

  function endChat(c, reason, notify) {
    if (notify && c.state !== 'ended') relay(c.peer, 'end').catch(() => {});
    Object.assign(c, { state: 'ended', keys: null, key: null, peerPub: null, safety: null, typingUntil: 0 });
    if (reason) note(c, reason);
  }

  async function request(peer) {
    let c = chats.get(peer);
    if (c && c.state !== 'ended') return open(peer);
    c = resetChat(peer, 'out');
    c.keys = await newKeys();
    note(c, `Chat request sent. Waiting for ${peer}…`);
    open(peer);
    try {
      await relay(peer, 'req', { pub: b64e(c.keys.pub) });
    } catch (e) {
      endChat(c, `Couldn't reach ${peer}: ${e.message}`, false);
      render();
    }
  }

  async function accept(c) {
    try {
      c.keys = await newKeys();
      const pub = b64e(c.keys.pub);
      await establish(c, c.peerPub);
      await relay(c.peer, 'acc', { pub });
      note(c, 'Connected and end-to-end encrypted. Compare safety codes with Verify to rule out interception.');
    } catch (e) {
      endChat(c, `Couldn't connect: ${e.message}`, true);
    }
    render();
  }

  function decline(c) {
    relay(c.peer, 'dec').catch(() => {});
    Object.assign(c, { state: 'ended', peerPub: null });
    note(c, 'You declined.');
    render();
  }

  async function onRelay(from, type, data) {
    if (blocked.has(from)) return;
    let c = chats.get(from);
    const hasPub = data && typeof data.pub === 'string';
    switch (type) {
      case 'req':
        if (!hasPub) return;
        // Both asked at once: the request from the alphabetically smaller name wins.
        if (c && c.state === 'out' && me < from) return;
        if (c && c.state === 'active') note(c, `${from} reconnected and asked to chat again. The old session is gone.`);
        c = resetChat(from, 'in');
        c.peerPub = data.pub;
        note(c, `${from} wants to chat.`);
        if (current !== from || document.hidden) c.unread++;
        break;
      case 'acc':
        if (!c || c.state !== 'out' || !hasPub) return;
        try {
          await establish(c, data.pub);
        } catch {
          endChat(c, 'Key exchange failed.', true);
          break;
        }
        note(c, 'Connected and end-to-end encrypted. Compare safety codes with Verify to rule out interception.');
        if (current !== from) c.unread++;
        break;
      case 'dec':
        if (!c || c.state !== 'out') return;
        endChat(c, `${from} declined.`, false);
        break;
      case 'end':
        if (!c || c.state === 'ended') return;
        endChat(c, c.state === 'in' ? `${from} withdrew the request.` : `${from} ended the chat.`, false);
        break;
      case 'typ':
        if (!c || c.state !== 'active') return;
        c.typingUntil = Date.now() + 4000;
        setTimeout(render, 4100);
        break;
      case 'msg': {
        if (!c || c.state !== 'active' || !data) return;
        let m;
        try {
          m = await unseal(c, data);
        } catch {
          note(c, 'A message failed to decrypt and was dropped.');
          break;
        }
        if (!Number.isInteger(m.n) || m.n <= c.recvSeq || typeof m.text !== 'string') {
          note(c, 'Dropped a replayed or malformed message.');
          break;
        }
        c.recvSeq = m.n;
        c.typingUntil = 0;
        push(c, 'them', m.text.slice(0, MAX_LEN));
        if (current !== from || document.hidden) c.unread++;
        break;
      }
      default:
        return;
    }
    render();
  }

  function onUsers(list) {
    online = list.filter(n => n !== me);
    for (const c of chats.values()) {
      if (c.state !== 'ended' && !online.includes(c.peer)) endChat(c, `${c.peer} went offline.`, false);
    }
    render();
  }

  function sendText() {
    const box = $('text');
    const c = chats.get(current);
    const text = box.value.trim();
    if (!c || c.state !== 'active' || !text) return;
    if (text.length > MAX_LEN) return toast(`Messages are limited to ${MAX_LEN} characters.`);
    box.value = '';
    autosize();
    outbox = outbox.then(async () => {
      if (c.state !== 'active') return;
      try {
        await relay(c.peer, 'msg', await seal(c, { n: ++c.sendSeq, text }));
        push(c, 'me', text);
      } catch (e) {
        toast(`Not sent: ${e.message}`);
        if (!box.value) box.value = text;
      }
      render();
    });
  }

  function typing() {
    const c = chats.get(current);
    if (!c || c.state !== 'active' || Date.now() - lastTyping < 3000) return;
    lastTyping = Date.now();
    relay(c.peer, 'typ').catch(() => {});
  }

  // ---------- rendering

  function open(peer) {
    current = peer;
    const c = chats.get(peer);
    if (c) c.unread = 0;
    $('safety').hidden = true;
    render();
    if (c && c.state === 'active') $('text').focus();
  }

  const badges = { out: 'waiting', in: 'request', ended: 'ended' };

  function render() {
    $('me').textContent = me;

    const chatList = $('chats');
    chatList.replaceChildren();
    for (const c of chats.values()) {
      const li = el('li');
      const b = el('button', c.peer === current ? 'sel' : '', c.peer);
      if (c.unread) b.append(el('span', 'badge', String(c.unread)));
      else if (badges[c.state]) b.append(el('span', `tag ${c.state}`, badges[c.state]));
      else b.append(el('span', 'tag lock', 'encrypted'));
      b.onclick = () => open(c.peer);
      li.append(b);
      chatList.append(li);
    }
    if (!chats.size) chatList.append(el('li', 'muted pad', 'No chats yet.'));

    const onlineList = $('online');
    onlineList.replaceChildren();
    const visible = online.filter(n => !blocked.has(n));
    for (const name of visible) {
      const li = el('li');
      const b = el('button', '', name);
      const c = chats.get(name);
      b.title = c && c.state !== 'ended' ? 'Open chat' : 'Send a chat request';
      b.onclick = () => request(name);
      li.append(b);
      onlineList.append(li);
    }
    if (!visible.length) onlineList.append(el('li', 'muted pad', 'Nobody else is here yet.'));

    const unread = [...chats.values()].reduce((n, c) => n + c.unread, 0);
    document.title = unread ? `(${unread}) Onion Chat` : 'Onion Chat';

    const c = current && chats.get(current);
    $('app').classList.toggle('show-chat', !!c);
    $('empty').hidden = !!c;
    $('chat').hidden = !c;
    if (!c) return;

    $('peer').textContent = c.peer;
    const typingNow = c.typingUntil > Date.now();
    $('status').textContent = {
      active: typingNow ? 'typing…' : 'end-to-end encrypted',
      out: 'waiting for a reply',
      in: 'wants to chat',
      ended: 'chat ended',
    }[c.state];
    $('verify').hidden = c.state !== 'active';
    $('end').hidden = c.state === 'ended';
    $('end').textContent = c.state === 'active' ? 'End' : 'Cancel';
    $('block').textContent = blocked.has(c.peer) ? 'Unblock' : 'Block';
    if (c.state !== 'active') $('safety').hidden = true;
    $('safety').textContent = c.safety
      ? `Safety code: ${c.safety}\nRead it to ${c.peer} over another channel. If it matches theirs, nobody is in the middle.`
      : '';

    const list = $('msgs');
    const stick = list.scrollHeight - list.scrollTop - list.clientHeight < 60;
    list.replaceChildren(...c.msgs.map(m => {
      const li = el('li', m.who);
      li.append(el('span', 'text', m.text), el('time', '', m.time));
      return li;
    }));
    if (stick) list.scrollTop = list.scrollHeight;

    const prompt = $('prompt');
    prompt.replaceChildren();
    if (c.state === 'in') {
      const yes = el('button', 'primary', 'Accept');
      const no = el('button', '', 'Decline');
      yes.onclick = () => accept(c);
      no.onclick = () => decline(c);
      prompt.append(el('span', '', `${c.peer} wants to start an encrypted chat.`), yes, no);
    } else if (c.state === 'ended' && online.includes(c.peer) && !blocked.has(c.peer)) {
      const again = el('button', 'primary', 'Start a new chat');
      again.onclick = () => request(c.peer);
      prompt.append(again);
    }
    prompt.hidden = !prompt.childElementCount;

    const composer = $('composer');
    composer.hidden = c.state !== 'active';
  }

  function autosize() {
    const t = $('text');
    t.style.height = 'auto';
    t.style.height = Math.min(t.scrollHeight, 160) + 'px';
    t.style.overflowY = t.scrollHeight > 160 ? 'auto' : 'hidden';
  }

  function setConnected(ok) {
    $('conn').classList.toggle('off', !ok);
    $('conn').title = ok ? 'Connected' : 'Reconnecting…';
  }

  // ---------- session

  function connect() {
    es = new EventSource('/api/events?t=' + encodeURIComponent(token));
    es.onopen = () => setConnected(true);
    es.onerror = () => {
      if (es.readyState === EventSource.CLOSED) sessionLost();
      else setConnected(false);
    };
    es.onmessage = e => {
      let ev;
      try { ev = JSON.parse(e.data); } catch { return; }
      if (ev.k === 'users' && Array.isArray(ev.users)) onUsers(ev.users);
      else if (ev.k === 'relay') inbox = inbox.then(() => onRelay(ev.from, ev.type, ev.data)).catch(() => {});
    };
  }

  function forget() {
    if (es) es.close();
    es = null;
    me = token = '';
    current = null;
    online = [];
    chats.clear();
    blocked.clear();
  }

  function sessionLost() {
    forget();
    $('app').hidden = true;
    $('join').hidden = false;
    $('join-err').textContent = 'Your session expired. Join again.';
    document.title = 'Onion Chat';
  }

  async function wipe() {
    leaving = true;
    for (const c of chats.values()) if (c.state !== 'ended') relay(c.peer, 'end').catch(() => {});
    await api('leave').catch(() => {});
    forget();
    location.replace('/');
  }

  // ---------- wiring

  if (!window.crypto || !crypto.subtle) {
    $('join-err').textContent = 'This browser can\'t do encryption here. Open the site over its .onion address in Tor Browser, or over HTTPS/localhost.';
    $('join-form').querySelector('button').disabled = true;
  }

  $('join-form').onsubmit = async e => {
    e.preventDefault();
    const btn = e.target.querySelector('button');
    btn.disabled = true;
    $('join-err').textContent = '';
    try {
      const r = await api('join', { name: $('name').value.trim() });
      me = r.name;
      token = r.token;
      connect();
      $('join').hidden = true;
      $('app').hidden = false;
      render();
    } catch (err) {
      $('join-err').textContent = err.message;
    } finally {
      btn.disabled = false;
    }
  };

  $('composer').onsubmit = e => { e.preventDefault(); sendText(); };
  $('text').onkeydown = e => {
    if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) { e.preventDefault(); sendText(); }
  };
  $('text').oninput = () => { autosize(); typing(); };
  $('back').onclick = () => { current = null; render(); };
  $('verify').onclick = () => { $('safety').hidden = !$('safety').hidden; };
  $('end').onclick = () => {
    const c = chats.get(current);
    if (c) { endChat(c, c.state === 'active' ? 'You ended the chat.' : 'You cancelled the request.', true); render(); }
  };
  $('block').onclick = () => {
    const c = chats.get(current);
    if (!c) return;
    if (blocked.delete(c.peer)) {
      note(c, `You unblocked ${c.peer}.`);
    } else {
      blocked.add(c.peer);
      if (c.state === 'in') relay(c.peer, 'dec').catch(() => {});
      endChat(c, `You blocked ${c.peer}. Their requests will be ignored.`, c.state !== 'in');
    }
    render();
  };
  $('wipe').onclick = wipe;

  document.addEventListener('visibilitychange', () => {
    if (!document.hidden && current) {
      const c = chats.get(current);
      if (c) { c.unread = 0; render(); }
    }
  });

  window.addEventListener('beforeunload', e => {
    if (!leaving && [...chats.values()].some(c => c.state === 'active')) e.preventDefault();
  });
  window.addEventListener('pagehide', () => {
    if (!token) return;
    fetch('/api/leave', { method: 'POST', keepalive: true, headers: { Authorization: 'Bearer ' + token } }).catch(() => {});
  });
})();
