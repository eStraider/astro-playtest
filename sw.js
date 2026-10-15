/*
 * Sealed playtest build: the service worker. Every game file on this site is
 * encrypted; a phone that has entered the password keeps the content key in
 * IndexedDB (non-extractable), and this worker decrypts each file as the game
 * asks for it. Without the key, navigations get the password page and
 * everything else is refused. Updates follow the app's native lifecycle: a new
 * worker waits until the old app is closed.
 */
const BUILD = '20261015194822-9e0948';
// Sites on the same github.io origin share the cache storage: each keeps its own.
const SITE = 'astro-playtest';
const CACHE = `lbcb-sealed-${SITE}-${BUILD}`;
// Caches from before per-site names ("lbcb-sealed-<build>") belong to the first site, playtest.
const LEGACY_CACHE = /^lbcb-sealed-\d{14}-[0-9a-f]{6}$/;
const PUBLIC = new Set(["gate.html","lock.json","robots.txt","icons/icon-192.png","icons/icon-512.png","icons/maskable-512.png","manifest.webmanifest"]);
const SEALED_IDS = ["710bc1851535b8da00254804","9f597cb239d1bae0772e5409","0046762c64464a27d59b4cb9","52cb22a854f8334bb491b625","2ebff640141429ac83924575","df281f5d3798a0ccc8a3c2b2","0eed6ebfeb0a3fd63a00f60a","55669c70cd3d98df9e255361","b30c1e6081d2cecb87cb2860","4baab1758be3cd40ef8327ed","6c576126d4fe8bdc7fb93bcf","6cfdca313df1d6fc85ad2829","eaa67e945593c212d266ea19","083da94b97e9dea224a365b0","be3a0676363694c7750d099e","c4b9b48076894eb28182bd31","d482700da96e6bdb96cdc06e","742b75333e46f76759c612b8","7e13e6182bc0d17408d3d2b8","b869ad593b4ec141453d9ebe","44d9be71bee8304d030ebc95","273e765743c213cf7c6b3283","ccc3cd604eecbfa690139a1b","6468458ac46d2cae95125f7e","73a901e6771a4a952dc55ef7","7bdb87e288d641914b28949f","40c6848c1381998a7d6000eb","df216aebed09fe23cc52b28e","912acd72792bf3650e9051a9","60eb4c8b827dd84ddefcb800","25ce4841b2917037786054bc","9f8a58977afbe45e271d9057","00d015f94ca2c0dd3ee1d719","c12208bd8a03ca15d9f39faf","c35fc911650b6d78677d7bbf","47bdc658aba0fb7b197150c4","20b65dbf7a6929ebfac68251","caf5338451da200616d79c91","70ff0361a70934739321b1c1","fdc8f8af56e65558cec914c2","7f730cce030c8cf7ee5ae66f","2644edb21d04b187efd2d1c1","8336c1f0a4f8c1de9532e305","c3daac80dec7c62042a13cc9","04968f83e53929faf57197ae","10a1634c7d2a04e1b5296e46","7d71b84bf200c30365fcb8b5","8fb1cf5ead2b612ca200629c","996e4e5c6d6894bfce03fee2","0a81041ac146807557250156","3fad10353225534cee2fb32c","01cc82a37056e7c419bf8251","b4863f579076e937f7f7826b","1803bccf33193fb4ee141e31","8d387994119a13d53e8ab361","4daf269055bf4b644d412d0d","e374381591059b2f7365dde4","421034af7b540770212a8fea","58bc7a5d50ac9b7123afeabc","ac21d55ea842ecef21e7d899","e474289cfc1da3ad9a5707b9","c7088ddffd4bcdeeaa2b0971","e61b10f9e26f77e6e678ebad","63318131c116929c8338b9f1","282ed9263831d5b459285be9","39d7d615bdb0c83ff59d4997","b7baa3e7aea188f3b225e90e","bc1dcbd5e42de2cabea5ac4c","f3f183a76d40b8043e548a10","9fac75909a0d0591ef9f333c","0e219ec44483480a64c73053","d150e81997e72b0a1d857aa6","d299a4f75ad75869d60c132f","d8c2c47c9fa6be7f144f75b6","6f33d2945a778e294d2f949a","9ae870a3e61b681547f32793","a968c346cca82e9ff9b9293d","6c68ccc85a3f101d33473bde","02b01ed1d66b945a04574201","9d2f2d3d664274c07986e541","1b2e79add432dd7f8b1660ce","094c6bdfca4bfed7e19ade3b","f71f201b3bc15d3878b3ac7a","2050a866a3f68e9e83171689","f33058508de13b8cf2d88ec7","66ca4d49dc2c20062dfe9d1c","234cc53278d758e1f3e93283"];

// --- sealed-crypto begin ---
const SEAL_ITERATIONS = 600000;
const sealEncoder = new TextEncoder();

function sealB64(bytes) {
  let text = '';
  for (const byte of new Uint8Array(bytes)) text += String.fromCharCode(byte);
  return btoa(text);
}

function sealUnB64(text) {
  return Uint8Array.from(atob(text), (c) => c.charCodeAt(0));
}

/** The password's key-encryption key for a lock's salt. */
async function sealPasswordKey(password, salt, iterations = SEAL_ITERATIONS) {
  const base = await crypto.subtle.importKey('raw', sealEncoder.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, base,
    { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

/** Opens a lock with a password: the content key (non-extractable), or null if the password is wrong. */
async function sealUnlock(lock, password) {
  const kek = await sealPasswordKey(password, sealUnB64(lock.salt), lock.iterations);
  try {
    const raw = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: sealUnB64(lock.iv), additionalData: sealEncoder.encode('lbcb-lock') },
      kek, sealUnB64(lock.wrapped));
    return crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['decrypt']);
  } catch {
    return null;
  }
}

/** Decrypts one sealed file (IV followed by ciphertext) stored under `path`. */
async function sealOpen(contentKey, path, sealed) {
  const bytes = new Uint8Array(sealed);
  return crypto.subtle.decrypt({ name: 'AES-GCM', iv: bytes.slice(0, 12), additionalData: sealEncoder.encode(path) },
    contentKey, bytes.slice(12));
}
// --- sealed-crypto end ---

// --- sealed-keystore begin ---
/* The content key, kept in IndexedDB as a non-extractable CryptoKey (page and worker share it). */
function sealDb() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open('lbcb-sealed', 1);
    request.onupgradeneeded = () => request.result.createObjectStore('keys');
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function sealKeyStore(mode, action) {
  const db = await sealDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction('keys', mode);
    const request = action(tx.objectStore('keys'));
    tx.oncomplete = () => { db.close(); resolve(request.result); };
    tx.onerror = () => { db.close(); reject(tx.error); };
  });
}

async function sealKeyGet() {
  try { return (await sealKeyStore('readonly', (store) => store.get('content'))) ?? null; } catch { return null; }
}

function sealKeyPut(key) {
  return sealKeyStore('readwrite', (store) => store.put(key, 'content'));
}

function sealKeyClear() {
  return sealKeyStore('readwrite', (store) => store.delete('content')).catch(() => undefined);
}
// --- sealed-keystore end ---

const scopePath = new URL(self.registration.scope).pathname;
let indexCache = null;

async function cached(path) {
  const cache = await caches.open(CACHE);
  const url = new URL(path, self.registration.scope).href;
  const hit = await cache.match(url);
  if (hit) return hit;
  const response = await fetch(url, { cache: 'no-store' });
  if (response.ok) await cache.put(url, response.clone());
  return response;
}

async function sealedIndex(key) {
  if (indexCache && indexCache.key === key) return indexCache.index;
  const response = await cached('sealed/index.bin');
  const plain = await sealOpen(key, 'index', await response.arrayBuffer());
  const index = JSON.parse(new TextDecoder().decode(plain));
  indexCache = { key, index };
  return index;
}

async function gate() {
  return cached('gate.html');
}

async function serveSealed(path, request) {
  const key = await sealKeyGet();
  const navigate = request.mode === 'navigate';
  if (!key) return navigate ? gate() : new Response('Locked', { status: 401 });
  let index;
  try {
    index = await sealedIndex(key);
  } catch {
    // The stored key belongs to another password: forget it and ask again.
    await sealKeyClear();
    return navigate ? gate() : new Response('Locked', { status: 401 });
  }
  let entry = index.files[path];
  if (!entry && navigate) {
    path = 'index.html';
    entry = index.files[path];
  }
  if (!entry) return fetch(request);
  const sealed = await cached(`sealed/${entry.id}.bin`);
  const body = await sealOpen(key, path, await sealed.arrayBuffer());
  return new Response(body, { headers: { 'Content-Type': entry.type, 'Cache-Control': 'no-store' } });
}

self.addEventListener('install', (event) => {
  event.waitUntil(caches.open(CACHE).then((cache) => cache.addAll([
    ...[...PUBLIC].filter((path) => path !== 'sw.js'),
    'sealed/index.bin',
    ...SEALED_IDS.map((id) => `sealed/${id}.bin`),
  ])));
});

self.addEventListener('activate', (event) => {
  event.waitUntil((async () => {
    for (const name of await caches.keys()) {
      const ours = name.startsWith(`lbcb-sealed-${SITE}-`) || (SITE === 'playtest' && LEGACY_CACHE.test(name));
      if (ours && name !== CACHE) await caches.delete(name);
    }
    await self.clients.claim();
  })());
});

self.addEventListener('message', (event) => {
  if (event.data && event.data.type === 'SKIP_WAITING') self.skipWaiting();
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  if (event.request.method !== 'GET' || url.origin !== self.location.origin || !url.pathname.startsWith(scopePath)) return;
  const path = decodeURIComponent(url.pathname.slice(scopePath.length));
  if (PUBLIC.has(path) || path.startsWith('sealed/')) {
    event.respondWith(cached(path));
    return;
  }
  event.respondWith(serveSealed(path === '' ? 'index.html' : path, event.request));
});
