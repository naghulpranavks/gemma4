/* ============================================
   EcoMesh Ranger Dashboard — Application Logic
   SSE-powered real-time alert feed + Leaflet map
   ============================================ */

(function () {
    "use strict";

    // --- Configuration ---
    const CONFIG = {
        apiBase: window.location.origin,
        sseEndpoint: "/api/alerts/stream",
        pollInterval: 10000,
        mapCenter: [-1.5023, 35.1800],  // Masai Mara — centered on 5-node mesh
        mapZoom: 11,
    };

    // --- State ---
    const state = {
        alerts: [],
        nodes: {},
        markers: {},
        filter: "all",
        mapReady: false,
        connected: false,
        initialLoad: true,  // suppress toasts on first fetch
    };

    // --- Threat metadata ---
    const THREATS = {
        CHAINSAW: { icon: "\u{1FAB5}", label: "Chainsaw", css: "chainsaw", color: "#ef4444" },
        GUNSHOT: { icon: "\u{1F4A5}", label: "Gunshot", css: "gunshot", color: "#dc2626" },
        VEHICLE: { icon: "\u{1F69A}", label: "Vehicle", css: "vehicle", color: "#f59e0b" },
        EXPLOSION: { icon: "\u{1F4A3}", label: "Explosion", css: "explosion", color: "#b91c1c" },
        TRAP_SNAP: { icon: "\u{1FAA4}", label: "Trap Snap", css: "trap_snap", color: "#8b5cf6" },
        DRONE: { icon: "\u{1F6F8}", label: "Drone", css: "drone", color: "#06b6d4" },
        DOG_BARK: { icon: "\u{1F415}", label: "Dog Bark", css: "dog_bark", color: "#ea580c" },
        AXE: { icon: "\u{1FA93}", label: "Axe Chop", css: "axe", color: "#d97706" },
        POACHER: { icon: "\u{1F4F7}", label: "Poacher Cam", css: "poacher", color: "#d946ef" },
        AMBIENT: { icon: "\u{1F33F}", label: "Ambient", css: "ambient", color: "#22c55e" },
        UNKNOWN: { icon: "\u{2753}", label: "Unknown", css: "ambient", color: "#6b7280" },
    };

    // =====================
    //  MAP INITIALIZATION
    // =====================
    let map;
    let markerLayer;

    // Sentinel node base positions (for persistent markers)
    const NODE_BASES = {
        1: { name: "Alpha", lat: -1.4725, lon: 35.2558, desc: "Forest Edge" },
        2: { name: "Bravo", lat: -1.5023, lon: 35.1447, desc: "Central Savanna" },
        3: { name: "Charlie", lat: -1.5341, lon: 35.2012, desc: "River Crossing" },
        4: { name: "Delta", lat: -1.4891, lon: 35.3105, desc: "East Boundary" },
        5: { name: "Echo", lat: -1.5150, lon: 35.0889, desc: "West Hilltop" },
    };

    function initMap() {
        map = L.map("map", {
            center: CONFIG.mapCenter,
            zoom: CONFIG.mapZoom,
            zoomControl: false,
            attributionControl: false,
        });

        // Dark tiles
        L.tileLayer(
            "https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png",
            { maxZoom: 19 }
        ).addTo(map);

        L.control.zoom({ position: "topright" }).addTo(map);
        L.control.scale({ position: "bottomleft", imperial: false, maxWidth: 120 }).addTo(map);
        markerLayer = L.layerGroup().addTo(map);

        // Protected zone polygon
        var protectedZone = L.polygon([
            [-1.44, 35.05], [-1.44, 35.33],
            [-1.56, 35.33], [-1.56, 35.05],
        ], {
            color: "#22c55e",
            weight: 2,
            fillColor: "#22c55e",
            fillOpacity: 0.04,
            dashArray: "8,6",
        }).addTo(map);
        protectedZone.bindTooltip("Protected Zone", {
            permanent: false,
            className: "zone-tooltip",
        });

        // Add sentinel node base markers with detection radius
        Object.keys(NODE_BASES).forEach(function (nid) {
            var nb = NODE_BASES[nid];

            // Detection radius circle (subtle)
            L.circle([nb.lat, nb.lon], {
                radius: 3000,
                color: "rgba(16, 185, 129, 0.15)",
                fillColor: "rgba(16, 185, 129, 0.03)",
                fillOpacity: 1,
                weight: 1,
                dashArray: "4,4",
                interactive: false,
            }).addTo(map);

            // Node base marker (small pulsing dot)
            var nodeIcon = L.divIcon({
                className: "",
                html: '<div class="node-base-marker">' +
                      '<div class="node-base-pulse"></div>' +
                      '<div class="node-base-dot"></div>' +
                      '<div class="node-base-label">' + nb.name + '</div>' +
                      '</div>',
                iconSize: [60, 60],
                iconAnchor: [30, 30],
            });
            var nodeMarker = L.marker([nb.lat, nb.lon], { icon: nodeIcon, interactive: true, zIndexOffset: -100 }).addTo(map);
            nodeMarker.bindTooltip(
                '<div class="node-tooltip-content">' +
                '<strong>' + nb.name + ' \u2014 ' + nb.desc + '</strong><br>' +
                '<span style="opacity:0.7">Sentinel Node #' + nid + '</span><br>' +
                '<span style="opacity:0.7">Detection radius: ~3 km</span>' +
                '</div>',
                { className: "node-tooltip", direction: "top", offset: [0, -12] }
            );
        });

        // Map legend
        var legend = L.control({ position: "bottomright" });
        legend.onAdd = function () {
            var div = L.DomUtil.create("div", "map-legend");
            var items = [
                ["#ef4444", "Chainsaw"], ["#dc2626", "Gunshot"],
                ["#f59e0b", "Vehicle"], ["#b91c1c", "Explosion"],
                ["#8b5cf6", "Trap Snap"], ["#06b6d4", "Drone"],
                ["#ea580c", "Dog Bark"], ["#d97706", "Axe Chop"],
                ["#d946ef", "Poacher Cam"], ["#22c55e", "Ambient"],
            ];
            var html = '<div class="legend-title">Threat Types</div>';
            items.forEach(function (item) {
                html += '<div class="legend-item"><span class="legend-dot" style="background:' + item[0] + '"></span> ' + item[1] + '</div>';
            });
            html += '<div class="legend-sep"></div>';
            html += '<div class="legend-item"><span class="legend-dot node-dot-legend"></span> Sentinel Node</div>';
            html += '<div class="legend-item"><span class="legend-dot" style="background:transparent;border:1px dashed #22c55e"></span> Protected Zone</div>';
            div.innerHTML = html;
            return div;
        };
        legend.addTo(map);

        // Map HUD — floating stats panel
        var hud = L.control({ position: "topleft" });
        hud.onAdd = function () {
            var div = L.DomUtil.create("div", "map-hud");
            div.id = "map-hud";
            div.innerHTML =
                '<div class="hud-title">LIVE STATUS</div>' +
                '<div class="hud-row"><span class="hud-label">Nodes Online</span><span class="hud-value" id="hud-nodes">0/5</span></div>' +
                '<div class="hud-row"><span class="hud-label">Threats Today</span><span class="hud-value hud-threat" id="hud-threats">0</span></div>' +
                '<div class="hud-row"><span class="hud-label">Last Event</span><span class="hud-value" id="hud-last">—</span></div>';
            return div;
        };
        hud.addTo(map);

        state.mapReady = true;
    }

    function updateMapHud() {
        var nodesOnline = 0;
        var nodeIds = Object.keys(state.nodes);
        nodeIds.forEach(function (id) {
            var n = state.nodes[id];
            var age = (Date.now() / 1000) - (n.timestamp || 0);
            if (age < 600) nodesOnline++;
        });

        var threatCount = 0;
        var lastThreatTime = null;
        state.alerts.forEach(function (a) {
            if (a.threat && !["AMBIENT", "UNKNOWN"].includes(a.threat.class)) {
                threatCount++;
                if (!lastThreatTime || a.timestamp > lastThreatTime) {
                    lastThreatTime = a.timestamp;
                }
            }
        });

        var hudNodes = document.getElementById("hud-nodes");
        var hudThreats = document.getElementById("hud-threats");
        var hudLast = document.getElementById("hud-last");

        if (hudNodes) hudNodes.textContent = nodesOnline + "/5";
        if (hudThreats) hudThreats.textContent = threatCount;
        if (hudLast && lastThreatTime) {
            var age = (Date.now() / 1000) - lastThreatTime;
            hudLast.textContent = formatTimeAgo(age);
        } else if (hudLast) {
            hudLast.textContent = "\u2014";
        }
    }

    function addMapMarker(alert) {
        if (!state.mapReady) return;
        const loc = alert.location;
        if (!loc || !loc.latitude || !loc.longitude) return;

        const meta = THREATS[alert.threat?.class] || THREATS.UNKNOWN;
        const isThreat = !["AMBIENT", "UNKNOWN"].includes(alert.threat?.class);
        const markerType = isThreat ? meta.css : "heartbeat";

        const icon = L.divIcon({
            className: "",
            html: '<div class="threat-marker ' + markerType + '">' + meta.icon + "</div>",
            iconSize: [32, 32],
            iconAnchor: [16, 16],
        });

        const marker = L.marker([loc.latitude, loc.longitude], { icon: icon })
            .addTo(markerLayer);

        marker.on("click", function () {
            showOverlay(alert);
        });

        // Animated ripple for threats
        if (isThreat) {
            var ripple = L.divIcon({
                className: "",
                html: '<div class="ripple-ring" style="border-color:' + meta.color + '"></div>',
                iconSize: [80, 80],
                iconAnchor: [40, 40],
            });
            var rippleMarker = L.marker([loc.latitude, loc.longitude], { icon: ripple, interactive: false })
                .addTo(markerLayer);
            // Remove ripple after animation completes
            setTimeout(function () { markerLayer.removeLayer(rippleMarker); }, 3000);

            map.flyTo([loc.latitude, loc.longitude], 13, { duration: 1.2 });
        }
    }

    function showOverlay(alert) {
        const threatClass = alert.threat?.class || "UNKNOWN";
        const meta = THREATS[threatClass] || THREATS.UNKNOWN;
        document.getElementById("overlay-icon").textContent = meta.icon;
        document.getElementById("overlay-label").textContent = meta.label + " Detected";

        const conf = alert.threat?.confidence || 0;
        const sev = getSeverity(alert);
        const ts = alert.timestamp_iso || new Date(alert.timestamp * 1000).toISOString();
        const nodeName = alert.node?.name || ("Node #" + (alert.node?.id || "?"));

        // Add visual verification snapshot for specific threats
        const hasImage = ["POACHER", "VEHICLE", "CHAINSAW", "AXE", "DRONE"].includes(threatClass);
        let imageHtml = "";
        if (hasImage) {
            let imgName = threatClass.toLowerCase();
            if (threatClass === "CHAINSAW" || threatClass === "AXE") imgName = "logging";
            imageHtml = '<div class="threat-snapshot-container">' +
                        '<img src="assets/images/' + imgName + '.png" class="threat-snapshot">' +
                        '<div class="snapshot-badge">REC</div>' +
                        '</div>';
        }

        document.getElementById("overlay-body").innerHTML =
            imageHtml +
            '<div class="detail-row"><span class="detail-label">Severity</span><span class="severity-badge severity-' + sev + '">' + sev.toUpperCase() + '</span></div>' +
            '<div class="detail-row"><span class="detail-label">Confidence</span><span class="detail-value">' + conf + '%</span></div>' +
            '<div class="detail-row"><span class="detail-label">Node</span><span class="detail-value">' + nodeName + '</span></div>' +
            '<div class="detail-row"><span class="detail-label">Time</span><span class="detail-value">' + formatTime(ts) + '</span></div>' +
            '<div class="detail-row"><span class="detail-label">Location</span><span class="detail-value">' +
            (alert.location?.latitude?.toFixed(5) || "?") + ', ' +
            (alert.location?.longitude?.toFixed(5) || "?") +
            '</span></div>' +
            '<div class="detail-row"><span class="detail-label">Battery</span><span class="detail-value">' + (alert.node?.battery_pct || "?") + '%</span></div>' +
            (alert.node?.audio_db ? '<div class="detail-row"><span class="detail-label">Audio Level</span><span class="detail-value">' + alert.node.audio_db + ' dB</span></div>' : '');

        document.getElementById("map-overlay").style.display = "block";
    }

    // =====================
    //  TAB NAVIGATION
    // =====================
    function initTabs() {
        document.querySelectorAll(".tab-btn").forEach(function (btn) {
            btn.addEventListener("click", function () {
                var tab = btn.dataset.tab;
                document.querySelectorAll(".tab-btn").forEach(function (b) { b.classList.remove("active"); });
                document.querySelectorAll(".tab-panel").forEach(function (p) { p.classList.remove("active"); });
                btn.classList.add("active");
                document.getElementById("panel-" + tab).classList.add("active");

                if (tab === "map" && map) {
                    setTimeout(function () { map.invalidateSize(); }, 100);
                }
                // Re-render nodes when switching to that tab
                if (tab === "nodes") {
                    renderNodes();
                }
                // Fetch analytics data when switching to analytics tab
                if (tab === "analytics") {
                    fetchStats();
                }
            });
        });

        document.getElementById("overlay-close").addEventListener("click", function () {
            document.getElementById("map-overlay").style.display = "none";
        });

        // Alert filters
        document.querySelectorAll(".filter-btn").forEach(function (btn) {
            btn.addEventListener("click", function () {
                document.querySelectorAll(".filter-btn").forEach(function (b) { b.classList.remove("active"); });
                btn.classList.add("active");
                state.filter = btn.dataset.filter;
                renderAlerts();
            });
        });
    }

    // =====================
    //  ALERT RENDERING
    // =====================
    function renderAlerts() {
        var list = document.getElementById("alert-list");
        var filtered = state.alerts;

        if (state.filter === "threats") {
            filtered = filtered.filter(function (a) {
                return !["AMBIENT", "UNKNOWN", "heartbeat"].includes(a.threat?.class) && a.msg_type !== "heartbeat";
            });
        }

        if (filtered.length === 0) {
            list.innerHTML =
                '<div class="empty-state"><p>No ' +
                (state.filter === "threats" ? "threat " : "") +
                'alerts yet.</p></div>';
            return;
        }

        list.innerHTML = "";
        filtered.forEach(function (alert, i) {
            list.appendChild(createAlertCard(alert, i === 0));
        });
    }

    function getSeverity(alert) {
        var cls = alert.threat?.class;
        var conf = alert.threat?.confidence || 0;
        var sev = alert.threat?.severity;
        if (sev) return sev; // Use server-provided severity
        if (cls === "GUNSHOT" && conf >= 80) return "critical";
        if (conf >= 80) return "critical";
        if (conf >= 60) return "warning";
        return "info";
    }

    function createAlertCard(alert, isNew) {
        var meta = THREATS[alert.threat?.class] || THREATS.UNKNOWN;
        var isThreat = !["AMBIENT", "UNKNOWN"].includes(alert.threat?.class) && alert.msg_type !== "heartbeat";
        var conf = alert.threat?.confidence || 0;
        var ts = alert.timestamp_iso || "";
        var severity = isThreat ? getSeverity(alert) : "info";

        var card = document.createElement("div");
        card.className = "alert-card " + (isThreat ? "threat" : "heartbeat") +
            (isThreat ? " severity-" + severity : "") +
            (isNew ? " new" : "");

        var confLevel = conf >= 80 ? "high" : conf >= 50 ? "medium" : "low";

        var severityBadge = "";
        if (isThreat) {
            var sevLabel = severity === "critical" ? "CRITICAL" : severity === "warning" ? "WARNING" : "INFO";
            severityBadge = '<span class="severity-badge severity-' + severity + '">' + sevLabel + '</span>';
        }

        var nodeName = alert.node?.name || ("Node #" + (alert.node?.id || "?"));

        card.innerHTML =
            '<div class="alert-icon-wrap ' + meta.css + '">' + meta.icon + '</div>' +
            '<div class="alert-content">' +
            '<div class="alert-title-row">' +
            '<div class="alert-title">' + meta.label + (isThreat ? " Detected" : "") + '</div>' +
            severityBadge +
            '</div>' +
            '<div class="alert-meta">' +
            '<span>' + nodeName + '</span>' +
            '<span>' + formatTime(ts) + '</span>' +
            (isThreat ? '<span>' + conf + '% conf</span>' : '') +
            '</div>' +
            (isThreat ? '<div class="confidence-bar"><div class="confidence-fill ' + confLevel + '" style="width:' + conf + '%"></div></div>' : '') +
            '</div>';

        card.addEventListener("click", function () {
            switchToMap();
            showOverlay(alert);
            if (alert.location?.latitude) {
                map.flyTo([alert.location.latitude, alert.location.longitude], 14, { duration: 1 });
            }
        });

        return card;
    }

    function switchToMap() {
        document.querySelectorAll(".tab-btn").forEach(function (b) { b.classList.remove("active"); });
        document.querySelectorAll(".tab-panel").forEach(function (p) { p.classList.remove("active"); });
        document.querySelector('[data-tab="map"]').classList.add("active");
        document.getElementById("panel-map").classList.add("active");
        setTimeout(function () { map.invalidateSize(); }, 150);
    }

    // =====================
    //  NODE STATUS
    // =====================
    function renderNodes() {
        var grid = document.getElementById("nodes-grid");
        var nodeIds = Object.keys(state.nodes);

        if (nodeIds.length === 0) {
            grid.innerHTML = '<div class="empty-state"><p>No nodes reporting yet.</p></div>';
            return;
        }

        grid.innerHTML = "";
        nodeIds.forEach(function (id) {
            var n = state.nodes[id];
            var age = (Date.now() / 1000) - (n.timestamp || 0);
            var online = age < 600; // 10 min timeout
            var nodeName = n.name || ("Sentinel #" + id);
            var nodeDesc = n.description || "";
            var env = n.environment || {};

            var card = document.createElement("div");
            card.className = "node-card";

            // Weather icon
            var weatherIcon = "\u2600\uFE0F"; // sunny default
            if (env.weather === "partly_cloudy") weatherIcon = "\u26C5";
            else if (env.weather === "overcast") weatherIcon = "\u2601\uFE0F";
            else if (env.weather === "light_rain") weatherIcon = "\uD83C\uDF27\uFE0F";

            // Signal strength indicator
            var signalBars = 4;
            var sigDbm = env.signal_strength_dbm || -60;
            if (sigDbm < -80) signalBars = 1;
            else if (sigDbm < -70) signalBars = 2;
            else if (sigDbm < -55) signalBars = 3;

            // Solar charging indicator
            var solarIcon = env.solar_charging ? "\u26A1" : "";

            card.innerHTML =
                '<div class="node-header">' +
                '<div class="node-name-group">' +
                '<span class="node-name">' + nodeName + '</span>' +
                (nodeDesc ? '<span class="node-desc">' + nodeDesc + '</span>' : '') +
                '</div>' +
                '<span class="node-status-badge ' + (online ? "online" : "offline") + '">' +
                (online ? "Online" : "Offline") +
                '</span>' +
                '</div>' +
                '<div class="node-stats">' +
                '<div class="node-stat"><div class="node-stat-value" style="color:' + batteryColor(n.battery_pct) + '">' + solarIcon + (n.battery_pct || "?") + '%</div><div class="node-stat-label">Battery</div></div>' +
                '<div class="node-stat"><div class="node-stat-value">' + (n.cpu_temp_c || "?") + '&deg;C</div><div class="node-stat-label">CPU Temp</div></div>' +
                '<div class="node-stat"><div class="node-stat-value">' + formatTimeAgo(age) + '</div><div class="node-stat-label">Last Seen</div></div>' +
                '</div>' +
                (env.weather ? '<div class="node-env-row">' +
                '<span>' + weatherIcon + ' ' + (env.ambient_temp_c || "?") + '&deg;C</span>' +
                '<span>\uD83D\uDCA7 ' + (env.humidity_pct || "?") + '%</span>' +
                '<span>\uD83D\uDCF6 ' + signalBars + '/4</span>' +
                (env.packet_loss_pct > 0 ? '<span style="color:var(--accent-amber)">Loss: ' + env.packet_loss_pct + '%</span>' : '') +
                '</div>' : '');
            grid.appendChild(card);
        });
    }

    // =====================
    //  SSE / POLLING
    // =====================
    function connectSSE() {
        try {
            var source = new EventSource(CONFIG.apiBase + CONFIG.sseEndpoint);

            source.onopen = function () {
                setConnectionStatus("connected", "Live");
                state.connected = true;
            };

            source.onmessage = function (event) {
                try {
                    var alert = JSON.parse(event.data);
                    // Skip if we already have this alert
                    var isDuplicate = state.alerts.find(function (e) {
                        return e.timestamp === alert.timestamp && e.node?.id === alert.node?.id;
                    });
                    if (!isDuplicate) {
                        handleNewAlert(alert, false);
                    }
                } catch (e) {
                    console.warn("SSE parse error:", e);
                }
            };

            source.onerror = function () {
                setConnectionStatus("error", "Disconnected");
                state.connected = false;
                source.close();
                // Reconnect after delay
                setTimeout(connectSSE, 5000);
            };
        } catch (e) {
            console.warn("SSE not available, falling back to polling");
            startPolling();
        }
    }

    function startPolling() {
        setConnectionStatus("connected", "Polling");
        fetchAlerts();
        setInterval(fetchAlerts, CONFIG.pollInterval);
    }

    function fetchAlerts() {
        fetch(CONFIG.apiBase + "/api/alerts?limit=50")
            .then(function (r) { return r.json(); })
            .then(function (data) {
                if (data.alerts && data.alerts.length > state.alerts.length) {
                    data.alerts.forEach(function (a) {
                        if (!state.alerts.find(function (e) { return e.timestamp === a.timestamp && e.node?.id === a.node?.id; })) {
                            handleNewAlert(a, state.initialLoad);
                        }
                    });
                }
                state.initialLoad = false;
                setConnectionStatus("connected", "Live");
            })
            .catch(function () {
                setConnectionStatus("error", "Offline");
            });
    }

    function handleNewAlert(alert, silent) {
        state.alerts.unshift(alert);
        if (state.alerts.length > 200) state.alerts.pop();

        // Update node status
        if (alert.node?.id) {
            state.nodes[alert.node.id] = {
                battery_pct: alert.node.battery_pct,
                cpu_temp_c: alert.node.cpu_temp_c,
                timestamp: alert.timestamp,
                last_seen: alert.timestamp_iso,
                name: alert.node.name || null,
                description: alert.node.description || null,
                environment: alert.environment || null,
            };
        }

        // Add marker
        addMapMarker(alert);

        // Update badge + toast (only for real-time alerts, not on page load)
        var isThreat = !["AMBIENT", "UNKNOWN"].includes(alert.threat?.class) && alert.msg_type !== "heartbeat";
        if (isThreat && !silent) {
            var badge = document.getElementById("alert-badge");
            var count = parseInt(badge.textContent || "0") + 1;
            badge.textContent = count;
            badge.style.display = "flex";
            showToast(alert);

            // Haptic feedback for critical threats on mobile
            var severity = getSeverity(alert);
            if (severity === "critical" && navigator.vibrate) {
                navigator.vibrate([200, 100, 200]);
            }
        }

        renderAlerts();
        renderNodes();
        updateMapHud();
    }

    // =====================
    //  TOAST NOTIFICATIONS
    // =====================
    function showToast(alert) {
        var container = document.getElementById("toast-container");
        // Limit to 3 visible toasts max
        while (container.children.length >= 3) {
            container.removeChild(container.firstChild);
        }
        var meta = THREATS[alert.threat?.class] || THREATS.UNKNOWN;
        var toast = document.createElement("div");
        toast.className = "toast threat";
        toast.innerHTML = meta.icon + " " + meta.label + " detected at Node #" + (alert.node?.id || "?") + " (" + (alert.threat?.confidence || 0) + "% conf)";

        container.appendChild(toast);
        setTimeout(function () {
            toast.style.opacity = "0";
            toast.style.transform = "translateY(-20px)";
            toast.style.transition = "all 0.3s ease";
            setTimeout(function () { toast.remove(); }, 300);
        }, 3000);
    }

    // =====================
    //  UTILITIES
    // =====================
    function setConnectionStatus(status, text) {
        var dot = document.querySelector(".status-dot");
        var label = document.querySelector(".status-text");
        dot.className = "status-dot " + status;
        label.textContent = text;
    }

    function formatTime(iso) {
        if (!iso) return "?";
        try {
            var d = new Date(iso);
            return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
        } catch (e) { return iso; }
    }

    function formatTimeAgo(seconds) {
        if (seconds < 60) return Math.floor(seconds) + "s";
        if (seconds < 3600) return Math.floor(seconds / 60) + "m";
        return Math.floor(seconds / 3600) + "h";
    }

    function batteryColor(pct) {
        if (!pct) return "#6b7280";
        if (pct > 60) return "#22c55e";
        if (pct > 30) return "#f59e0b";
        return "#ef4444";
    }

    // =====================
    //  ANALYTICS
    // =====================
    function fetchStats() {
        fetch(CONFIG.apiBase + "/api/stats")
            .then(function (r) { return r.json(); })
            .then(function (data) {
                renderStats(data);
                drawThreatChart(data.threat_counts);
                drawHourlyChart(data.hourly_activity);
                renderNodeStatsTable(data.node_stats);
            })
            .catch(function (e) { console.warn("Stats fetch error:", e); });
    }

    function renderStats(data) {
        // Summary cards
        var threatEl = document.querySelector("#stat-total-threats .stat-number");
        var nodesEl = document.querySelector("#stat-active-nodes .stat-number");
        var uptimeEl = document.querySelector("#stat-uptime .stat-number");
        var reportsEl = document.querySelector("#stat-total-reports .stat-number");

        if (threatEl) threatEl.textContent = data.total_threats || 0;
        if (nodesEl) nodesEl.textContent = data.active_nodes || 0;
        if (reportsEl) reportsEl.textContent = data.total_alerts || 0;

        if (uptimeEl) {
            var sec = data.uptime_seconds || 0;
            if (sec < 60) uptimeEl.textContent = Math.floor(sec) + "s";
            else if (sec < 3600) uptimeEl.textContent = Math.floor(sec / 60) + "m";
            else uptimeEl.textContent = (sec / 3600).toFixed(1) + "h";
        }
    }

    function drawThreatChart(threatCounts) {
        var canvas = document.getElementById("chart-threats");
        if (!canvas) return;
        var ctx = canvas.getContext("2d");
        var dpr = window.devicePixelRatio || 1;

        canvas.width = canvas.offsetWidth * dpr;
        canvas.height = 180 * dpr;
        canvas.style.height = "180px";
        ctx.scale(dpr, dpr);

        var w = canvas.offsetWidth;
        var h = 180;
        ctx.clearRect(0, 0, w, h);

        var threats = [
            { key: "CHAINSAW", label: "Chainsaw", color: "#ef4444", icon: "\uD83E\uDEB5" },
            { key: "GUNSHOT", label: "Gunshot", color: "#dc2626", icon: "\uD83D\uDCA5" },
            { key: "VEHICLE", label: "Vehicle", color: "#f59e0b", icon: "\uD83D\uDE9A" },
        ];

        var maxVal = 1;
        threats.forEach(function (t) {
            var v = threatCounts[t.key] || 0;
            if (v > maxVal) maxVal = v;
        });

        var barH = 32;
        var gap = 16;
        var labelW = 100;
        var startY = 20;

        threats.forEach(function (t, i) {
            var y = startY + i * (barH + gap);
            var val = threatCounts[t.key] || 0;
            var barW = ((w - labelW - 60) * val) / maxVal;

            // Label
            ctx.fillStyle = "#e8ecf4";
            ctx.font = "600 13px Inter, sans-serif";
            ctx.textAlign = "left";
            ctx.fillText(t.icon + " " + t.label, 8, y + barH / 2 + 5);

            // Bar background
            ctx.fillStyle = "rgba(255,255,255,0.04)";
            ctx.beginPath();
            ctx.roundRect(labelW, y, w - labelW - 60, barH, 6);
            ctx.fill();

            // Bar fill
            if (barW > 0) {
                ctx.fillStyle = t.color;
                ctx.globalAlpha = 0.85;
                ctx.beginPath();
                ctx.roundRect(labelW, y, Math.max(barW, 8), barH, 6);
                ctx.fill();
                ctx.globalAlpha = 1;
            }

            // Value
            ctx.fillStyle = "#e8ecf4";
            ctx.font = "700 14px Inter, sans-serif";
            ctx.textAlign = "left";
            ctx.fillText(val.toString(), labelW + barW + 10, y + barH / 2 + 5);
        });
    }

    function drawHourlyChart(hourlyData) {
        var canvas = document.getElementById("chart-hourly");
        if (!canvas) return;
        var ctx = canvas.getContext("2d");
        var dpr = window.devicePixelRatio || 1;

        canvas.width = canvas.offsetWidth * dpr;
        canvas.height = 160 * dpr;
        canvas.style.height = "160px";
        ctx.scale(dpr, dpr);

        var w = canvas.offsetWidth;
        var h = 160;
        ctx.clearRect(0, 0, w, h);

        var padL = 30;
        var padR = 10;
        var padT = 10;
        var padB = 30;
        var chartW = w - padL - padR;
        var chartH = h - padT - padB;

        var maxTotal = 1;
        hourlyData.forEach(function (d) {
            if (d.total > maxTotal) maxTotal = d.total;
        });

        var barW = Math.max(chartW / 24 - 2, 3);
        var now = new Date().getHours();

        hourlyData.forEach(function (d, i) {
            var x = padL + (i / 24) * chartW + 1;
            var totalH = (d.total / maxTotal) * chartH;
            var threatH = (d.threats / maxTotal) * chartH;

            // Total bar (green/dim)
            ctx.fillStyle = "rgba(34, 197, 94, 0.2)";
            ctx.beginPath();
            ctx.roundRect(x, padT + chartH - totalH, barW, totalH, 2);
            ctx.fill();

            // Threat portion (red)
            if (threatH > 0) {
                ctx.fillStyle = "rgba(239, 68, 68, 0.7)";
                ctx.beginPath();
                ctx.roundRect(x, padT + chartH - threatH, barW, threatH, 2);
                ctx.fill();
            }

            // Current hour highlight
            if (i === now) {
                ctx.strokeStyle = "#22c55e";
                ctx.lineWidth = 1.5;
                ctx.beginPath();
                ctx.roundRect(x - 1, padT, barW + 2, chartH, 2);
                ctx.stroke();
            }
        });

        // X-axis labels
        ctx.fillStyle = "#5a6478";
        ctx.font = "500 9px Inter, sans-serif";
        ctx.textAlign = "center";
        [0, 6, 12, 18].forEach(function (hr) {
            var x = padL + (hr / 24) * chartW + barW / 2;
            var label = hr === 0 ? "12a" : hr < 12 ? hr + "a" : hr === 12 ? "12p" : (hr - 12) + "p";
            ctx.fillText(label, x, h - 8);
        });

        // Y-axis label
        ctx.fillStyle = "#5a6478";
        ctx.font = "500 9px Inter, sans-serif";
        ctx.textAlign = "right";
        ctx.fillText(maxTotal.toString(), padL - 5, padT + 10);
        ctx.fillText("0", padL - 5, padT + chartH);
    }

    function renderNodeStatsTable(nodeStats) {
        var container = document.getElementById("node-stats-table");
        if (!container) return;

        if (!nodeStats || nodeStats.length === 0) {
            container.innerHTML = '<div class="empty-state"><p>No node data yet.</p></div>';
            return;
        }

        var html = '<table class="stats-table">';
        html += '<thead><tr><th>Node</th><th>Reports</th><th>Threats</th><th>Avg Bat</th><th>Avg Temp</th></tr></thead>';
        html += '<tbody>';
        nodeStats.forEach(function (ns) {
            var threatPct = ns.total_reports > 0 ? ((ns.threat_count / ns.total_reports) * 100).toFixed(0) : 0;
            html += '<tr>';
            html += '<td>#' + ns.node_id + '</td>';
            html += '<td>' + ns.total_reports + '</td>';
            html += '<td><span style="color:' + (ns.threat_count > 0 ? '#ef4444' : '#22c55e') + '">' + ns.threat_count + '</span> <span style="color:#5a6478;font-size:0.7rem">(' + threatPct + '%)</span></td>';
            html += '<td style="color:' + batteryColor(ns.avg_battery) + '">' + ns.avg_battery + '%</td>';
            html += '<td>' + ns.avg_temp + '&deg;C</td>';
            html += '</tr>';
        });
        html += '</tbody></table>';
        container.innerHTML = html;
    }

    // =====================
    //  MOBILE GESTURES
    // =====================
    function initSwipeGestures() {
        var tabOrder = ["map", "alerts", "nodes", "analytics"];
        var touchStartX = 0;
        var touchStartY = 0;
        var content = document.getElementById("content");

        content.addEventListener("touchstart", function (e) {
            touchStartX = e.changedTouches[0].screenX;
            touchStartY = e.changedTouches[0].screenY;
        }, { passive: true });

        content.addEventListener("touchend", function (e) {
            var dx = e.changedTouches[0].screenX - touchStartX;
            var dy = e.changedTouches[0].screenY - touchStartY;

            // Only trigger if horizontal swipe is dominant and > 50px
            if (Math.abs(dx) > 50 && Math.abs(dx) > Math.abs(dy) * 1.5) {
                var activeBtn = document.querySelector(".tab-btn.active");
                var currentTab = activeBtn ? activeBtn.dataset.tab : "map";
                var currentIdx = tabOrder.indexOf(currentTab);

                var nextIdx;
                if (dx < 0) {
                    // Swipe left → next tab
                    nextIdx = Math.min(currentIdx + 1, tabOrder.length - 1);
                } else {
                    // Swipe right → prev tab
                    nextIdx = Math.max(currentIdx - 1, 0);
                }

                if (nextIdx !== currentIdx) {
                    var btn = document.querySelector('[data-tab="' + tabOrder[nextIdx] + '"]');
                    if (btn) btn.click();
                }
            }
        }, { passive: true });
    }

    function initPullToRefresh() {
        var alertList = document.getElementById("alert-list");
        var pullStartY = 0;
        var pulling = false;

        alertList.addEventListener("touchstart", function (e) {
            if (alertList.scrollTop === 0) {
                pullStartY = e.touches[0].screenY;
                pulling = true;
            }
        }, { passive: true });

        alertList.addEventListener("touchend", function (e) {
            if (pulling) {
                var dy = e.changedTouches[0].screenY - pullStartY;
                if (dy > 80) {
                    // Pull-to-refresh triggered
                    fetchAlerts();
                    // Brief visual feedback
                    alertList.style.transition = "transform 0.2s";
                    alertList.style.transform = "translateY(0)";
                    setTimeout(function () { alertList.style.transition = ""; }, 300);
                }
                pulling = false;
            }
        }, { passive: true });
    }

    // =====================
    //  BOOTSTRAP
    // =====================
    function init() {
        initMap();
        initTabs();
        initSwipeGestures();
        initPullToRefresh();
        // Force map to recalculate size after layout is ready
        setTimeout(function () {
            if (map) map.invalidateSize();
        }, 500);
        // Try SSE first, fall back to polling
        connectSSE();
        // Initial fetch
        fetchAlerts();
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init);
    } else {
        init();
    }
})();
