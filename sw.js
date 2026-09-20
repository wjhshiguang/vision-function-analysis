/* 视功能自动分析工作台 · Service Worker
   作用：让页面可以离线打开（PWA）。
   注意：本 SW 只缓存页面的静态资源（HTML / manifest / 图标），
        不使用任何服务器存储；业务数据全部保存在浏览器 localStorage 中，SW 不接触、不上传。 */
const CACHE = 'vision-workbench-v1.1.1';
const ASSETS = [
  './index.html',
  './manifest.json',
  './icons/icon-192.png',
  './icons/icon-512.png',
  './icons/apple-touch-icon.png',
  './icons/favicon.png'
];

self.addEventListener('install', function(e){
  e.waitUntil(
    caches.open(CACHE).then(function(c){
      return Promise.all(ASSETS.map(function(u){
        return c.add(u).catch(function(){ return null; });
      }));
    }).then(function(){ return self.skipWaiting(); })
  );
});

self.addEventListener('activate', function(e){
  e.waitUntil(
    caches.keys().then(function(keys){
      return Promise.all(keys.map(function(k){
        return k === CACHE ? null : caches.delete(k);
      }));
    }).then(function(){ return self.clients.claim(); })
  );
});

self.addEventListener('message', function(e){
  if (e.data === 'skipWaiting') self.skipWaiting();
});

self.addEventListener('fetch', function(e){
  const req = e.request;
  if (req.method !== 'GET') return;
  let url;
  try { url = new URL(req.url); } catch (err) { return; }
  /* 只处理同源请求，绝不介入任何跨域/外部数据请求 */
  if (url.origin !== self.location.origin) return;

  /* 页面导航：带缓存版本参数回源 —— 托管网关会按路径缓存旧页面，
     加版本参数可以稳定绕开它，保证每次打开拿到最新版本；失败时回落到缓存 → 离线也能打开 */
  if (req.mode === 'navigate') {
    const fresh = self.registration.scope + 'index.html?sw=' + CACHE;
    e.respondWith(
      fetch(fresh, { cache: 'reload', credentials: 'same-origin' }).then(function(res){
        if (!res || res.status !== 200) throw new Error('fresh fetch failed');
        const cp = res.clone();
        caches.open(CACHE).then(function(c){ c.put('./index.html', cp); });
        return res;
      }).catch(function(){
        return caches.match('./index.html').then(function(r){
          return r || new Response('离线中，且本地缓存尚未建立。请联网打开一次后再试。', {
            status: 200, headers: { 'Content-Type': 'text/plain; charset=utf-8' }
          });
        });
      })
    );
    return;
  }

  /* 静态资源：缓存优先，后台补充 */
  e.respondWith(
    caches.match(req).then(function(cached){
      if (cached) return cached;
      return fetch(req).then(function(res){
        if (res && res.status === 200 && res.type === 'basic') {
          const cp = res.clone();
          caches.open(CACHE).then(function(c){ c.put(req, cp); });
        }
        return res;
      }).catch(function(){
        return caches.match('./index.html');
      });
    })
  );
});
