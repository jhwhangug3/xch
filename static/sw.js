self.addEventListener('install', (event) => {
    self.skipWaiting();
});

self.addEventListener('activate', (event) => {
    event.waitUntil(self.clients.claim());
});

// Show notification when a push arrives
self.addEventListener('push', (event) => {
    try {
        const data = event.data ? event.data.json() : {};
        const title = data.title || 'meowCHAT';
        const body = data.body || 'New message';
        const url = data.url || '/dashboard';
        const options = {
            body,
            icon: '/static/images/fav.png',
            badge: '/static/images/fav.png',
            data: { url }
        };
        event.waitUntil(self.registration.showNotification(title, options));
    } catch (e) {
        // Fallback if not JSON
        event.waitUntil(self.registration.showNotification('meowCHAT', { body: 'New message' }));
    }
});

self.addEventListener('notificationclick', (event) => {
    event.notification.close();
    const url = (event.notification.data && event.notification.data.url) || '/dashboard';
    event.waitUntil(
        self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((clientList) => {
            for (const client of clientList) {
                if ('focus' in client) return client.focus();
            }
            if (self.clients.openWindow) return self.clients.openWindow(url);
        })
    );
});


