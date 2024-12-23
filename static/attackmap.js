
// Define the offline zoom max constant
const onlineZoomMax = 17;
const offlineZoomMax = 7;
const tileZoomMax = 7;
const tileZoomMin = 3;
const tileDefaultZoom = 3;
var map_switched_type = window.map_switched_type;

// display max incident on live threat table
const MAX_INCIDENTS = 100;

// Set current map name to "Transport Map"
var currentMapName = window.map_default_tile_name;

// Function to create a tile layer
function createTileLayer(urlTemplate, options) {
    return L.tileLayer(urlTemplate, options);
}

// URLs for different map types
const mapUrls = {
    "Dark Map": {
        online: 'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png',
        offline: '/static/tiles/dark_all/{z}/{x}/{y}{r}.png'
    },
    "Light Map": {
        online: 'https://{s}.basemaps.cartocdn.com/light_all/{z}/{x}/{y}{r}.png',
        offline: '/static/tiles/light_all/{z}/{x}/{y}{r}.png'
    },
    "Voyager Map": {
        online: 'https://{s}.basemaps.cartocdn.com/rastertiles/voyager/{z}/{x}/{y}{r}.png',
        offline: '/static/tiles/voyager/{z}/{x}/{y}{r}.png'
    },
    "Spotify Dark Map": {
        online: 'https://{s}.basemaps.cartocdn.com/spotify_dark/{z}/{x}/{y}{r}.png',
        offline: '/static/tiles/spotify_dark/{z}/{x}/{y}{r}.png'
    },
    "Transport Map": {
        online: 'https://{s}.tile.thunderforest.com/transport/{z}/{x}/{y}{r}.png?apikey=6e5478c8a4f54c779f85573c0e399391',
        offline: '/static/tiles/transport/{z}/{x}/{y}{r}.png'
    },
    "Cycle Map": {
        online: 'https://{s}.tile.thunderforest.com/cycle/{z}/{x}/{y}{r}.png?apikey=6e5478c8a4f54c779f85573c0e399391',
        offline: '/static/tiles/cycle/{z}/{x}/{y}{r}.png'
    }
};

// Define base layers globally
window.layerDarkMap = createTileLayer(mapUrls["Dark Map"][map_switched_type], {
    attribution: 'Map: Dark',
    detectRetina: true,
    subdomains: 'abcd',
    tileSize: 256,
});

window.layerLightMap = createTileLayer(mapUrls["Light Map"][map_switched_type], {
    attribution: 'Map: Light',
    detectRetina: true,
    subdomains: 'abcd',
    tileSize: 256,
});

window.layerVoyagerMap = createTileLayer(mapUrls["Voyager Map"][map_switched_type], {
    attribution: 'Map: Voyager',
    detectRetina: true,
    subdomains: 'abcd',
    tileSize: 256,
});

window.layerSpotifyDarkMap = createTileLayer(mapUrls["Spotify Dark Map"][map_switched_type], {
    attribution: 'Map: Spotify Dark',
    detectRetina: true,
    subdomains: 'abcd',
    tileSize: 256,
});

window.layerTransportMap = createTileLayer(mapUrls["Transport Map"][map_switched_type], {
    attribution: 'Map: Transport',
    detectRetina: true,
    subdomains: 'abc',
    tileSize: 256,
});

window.layerCycleMap = createTileLayer(mapUrls["Cycle Map"][map_switched_type], {
    attribution: 'Map: Cycle',
    detectRetina: true,
    subdomains: 'abc',
    tileSize: 256,
});

// layers and order
const tileLayers = {
    "Dark Map": window.layerDarkMap,
    "Spotify Dark Map": window.layerSpotifyDarkMap,
    "Light Map": window.layerLightMap,
    "Voyager Map": window.layerVoyagerMap,
    "Transport Map": window.layerTransportMap,
    "Cycle Map": window.layerCycleMap
};

// Mapping of layer names to image file names
const tileLayersImages = {
    "Dark Map": "dark_map.png",
    "Light Map": "light_map.png",
    "Voyager Map": "voyager_map.png",
    "Spotify Dark Map": "spotify_dark_map.png",
    "Transport Map": "transport_map.png",
    "Cycle Map": "cycle_map.png"
};

// Initialize map
var map = L.map('map', {
    layers: [window.layerTransportMap],
    center: new L.LatLng(33, 23),
    tap: false,
    trackResize: true,
    worldCopyJump: true,
    zoom: tileDefaultZoom,
    minZoom: tileZoomMin,
    maxZoom: tileZoomMax,
    fullscreenControl: false,
    zoomControl: false,
    attributionControl: false,
    zoomSnap: 0.5,
    zoomDelta: 0.5,
    // zoomAnimation: false
});


document.getElementById("flexSwitchOnlineMap").addEventListener("change", function() {
    if (this.checked) {
        map_switched_type='online';
        console.log("Switched maps mode to online");
    } else {
        map_switched_type='offline';
        console.log("Switched maps mode to offline");
    }
});

// Add custom controls if needed
var ControlTools = L.Control.Tools();
ControlTools.addTo(map);

// Append <svg> to map
var svg = d3.select(map.getPanes().overlayPane).append("svg").attr("class", "leaflet-zoom-animated").attr("width", window.innerWidth).attr("height", window.innerHeight);

function translateSVG() {

    var viewBoxLeft = document.querySelector("svg.leaflet-zoom-animated").viewBox.animVal.x;
    var viewBoxTop = document.querySelector("svg.leaflet-zoom-animated").viewBox.animVal.y;

    // Resizing width and height in case of window resize
    svg.attr("width", window.innerWidth);
    svg.attr("height", window.innerHeight);

    // Adding the ViewBox attribute to our SVG to contain it
    svg.attr("viewBox", function () {
        return "" + viewBoxLeft + " " + viewBoxTop + " "  + window.innerWidth + " " + window.innerHeight;
    });

    // Adding the style attribute to our SVG to translate it
    svg.attr("style", function () {
        return "transform: translate3d(" + viewBoxLeft + "px, " + viewBoxTop + "px, 0px);";
    });
}


// Call the translate function whenever the map is zoomed or panned
map.on("moveend", function() {
    console.log("Resizing animated area...")
    translateSVG();
});

function getFontSize(zoom) {
    return Math.max(14, 26 - (zoom * 2)); // adjust the formula to your liking
}
  
// Update the font size when the zoom level changes
map.on('zoomend', function() {
    var zoom = map.getZoom();
    var fontSize = getFontSize(zoom);
    $('.leaflet-popup-content').css('font-size', fontSize + 'px');
});


function calcMidpoint(x1, y1, x2, y2, bend) {
    try {
        if(y2<y1 && x2<x1) {
            var tmpy = y2;
            var tmpx = x2;
            x2 = x1;
            y2 = y1;
            x1 = tmpx;
            y1 = tmpy;
        }
        else if(y2<y1) {
            y1 = y2 + (y2=y1, 0);
        }
        else if(x2<x1) {
            x1 = x2 + (x2=x1, 0);
        }

        var radian = Math.atan(-((y2-y1)/(x2-x1)));
        var r = Math.sqrt(x2-x1) + Math.sqrt(y2-y1);
        var m1 = (x1+x2)/2;
        var m2 = (y1+y2)/2;

        var min = 2.5, max = 7.5;
        //var min = 1, max = 7;
        var arcIntensity = parseFloat((Math.random() * (max - min) + min).toFixed(2));

        if (bend === true) {
            var a = Math.floor(m1 - r * arcIntensity * Math.sin(radian));
            var b = Math.floor(m2 - r * arcIntensity * Math.cos(radian));
        } else {
            var a = Math.floor(m1 + r * arcIntensity * Math.sin(radian));
            var b = Math.floor(m2 + r * arcIntensity * Math.cos(radian));
        }

        return {"x":a, "y":b};
    }
    catch(err) {
        console.log(err.message);
    }
}

function translateAlong(path) {
    try {
        var l = path.getTotalLength();
        return function(i) {
            return function(t) {
                // Put in try/catch because sometimes floating point is stupid..
                try {
                    var p = path.getPointAtLength(t*l);
                    return "translate(" + p.x + "," + p.y + ")";
                } catch(err){
                    console.log(err);
                    return "ERROR";
                }
            }
        }
    }
    catch(err) {
        console.log(err.message);
    }       
}

function handleSourceParticle(color, srcPoint) {
    try {
        var i = 0;
        var x = srcPoint['x'];
        var y = srcPoint['y'];

        svg.append('circle')
            .attr('cx', x)
            .attr('cy', y)
            .attr('r', 0)
            .style('fill', 'none')
            .style('stroke', color)
            .style('stroke-opacity', 1)
            .style('stroke-width', 3)
            .transition()
            .duration(700)
            .ease(d3.easeCircleIn)
            // Circle radius source animation
            .attr('r', 50)
            .style('stroke-opacity', 0)
            .remove();
    
    }
    catch(err) {
        console.log(err.message);
    }

}

function handleSourceParticle2(color, srcPoint) {
    try {
        var i = 0;
        var x = srcPoint['x'];
        var y = srcPoint['y'];

        svg.append('circle')
            .attr('cx', x)
            .attr('cy', y)
            .attr('r', 1e-6)
            .style('fill', 'none')
            //.style('stroke', d3.hsl((i = (i + 1) % 360), 1, .5))
            .style('stroke', color)
            .style('stroke-opacity', 1)
            .transition()
            .duration(2000)
            .ease(Math.sqrt)
            .attr('r', 35)
            .style('stroke-opacity', 1e-6)
            .remove();
    }
    catch(err) {
        console.log(err.message);
    }
}


function drawTrafficLine(color, srcPoint, hqPoint) {
    var fromX = srcPoint['x'];
    var fromY = srcPoint['y'];
    var toX = hqPoint['x'];
    var toY = hqPoint['y'];
    var bendArray = [true, false];
    var bend = bendArray[Math.floor(Math.random() * bendArray.length)];

    var lineData = [srcPoint, calcMidpoint(fromX, fromY, toX, toY, bend), hqPoint]
    var lineFunction = d3.line()
        .curve(d3.curveBasis)
        .x(function(d) {return d.x;})
        .y(function(d) {return d.y;});

    var lineGraph = svg.append('path')
            .attr('d', lineFunction(lineData))
            .attr('opacity', 0.8)
            .attr('stroke', color)
            .attr('stroke-width', 2)
            .attr('fill', 'none');

    var circleRadius = 6

    // Circle follows the line
    var dot = svg.append('circle')
        .attr('r', circleRadius)
        .attr('fill', color)
        .transition()
        .duration(700)
        .ease(d3.easeCircleIn)
        .attrTween('transform', translateAlong(lineGraph.node()))
        .on('end', function() {
            d3.select(this)
                .attr('fill', 'none')
                .attr('stroke', color)
                .attr('stroke-width', 3)
                .transition()
                .duration(700)
                .ease(d3.easeCircleIn)
                // Circle radius destination animation
                .attr('r', 50)
                .style('stroke-opacity', 0)
                .remove();
    });

    var length = lineGraph.node().getTotalLength();
    lineGraph.attr('stroke-dasharray', length + ' ' + length)
        .attr('stroke-dashoffset', length)
        .transition()
        .duration(700)
        .ease(d3.easeCircleIn)
        .attr('stroke-dashoffset', 0)
        .on('end', function() {
            d3.select(this)
                .transition()
                .duration(700)
                .style('opacity', 0)
                .remove();
    });
}

function drawTrafficLin2(color, srcPoint, hqPoint) {
    try {
        var fromX = srcPoint['x'];
        var fromY = srcPoint['y'];
        var toX = hqPoint['x'];
        var toY = hqPoint['y'];


        var bendArray = [true, false];
        var bend = bendArray[Math.floor(Math.random() * bendArray.length)];

        var lineData = [srcPoint, calcMidpoint(fromX, fromY, toX, toY, bend), hqPoint]
        
        // d3.v6 
        //var lineFunction = d3.line()
        //     .x(function(d) {return d.x;})
        //     .y(function(d) {return d.y;})
        //     .curve(d3.curveLinear);

        // interpolate("basis")
        // interpolate("linear")

                
        if (fromX === toX && fromY === toY){
            
            return;  
        }

        var lineFunction = d3.svg.line().interpolate("basis").x(function(d) {return d.x;}).y(function(d) {return d.y;});
        var lineGraph = svg.append('path').attr('d', lineFunction(lineData)).attr('opacity', 0.8).attr('stroke', color).attr('stroke-width', 2).attr('fill', 'none');

        if (translateAlong(lineGraph.node()) === 'ERROR') {
            console.log('translateAlong ERROR')
            return;
        }

        var circleRadius = 6

        // Circle follows the line
        var dot = svg.append('circle')
            .attr('r', circleRadius)
            .attr('fill', color)
            .transition()
            .duration(700)
            .ease('ease-in')
            .attrTween('transform', translateAlong(lineGraph.node()))
            .each('end', function() {
                d3.select(this)
                    .transition()
                    .duration(500)
                    .attr('r', circleRadius * 2.5)
                    .style('opacity', 0)
                    .remove();
        });

        var length = lineGraph.node().getTotalLength();
        lineGraph.attr('stroke-dasharray', length + ' ' + length)
            .attr('stroke-dashoffset', length)
            .transition()
            .duration(700)
            .ease('ease-in')
            .attr('stroke-dashoffset', 0)
            .each('end', function() {
                d3.select(this)
                    .transition()
                    .duration(100)
                    .style('opacity', 0)
                    .remove();
        });
    }
    catch(err) {
        console.log(err.message);
      }
}


var circles = new L.LayerGroup();
map.addLayer(circles);
var markers = new L.LayerGroup();
map.addLayer(markers);

var circlesObject = {};

function addSourceCircle(country, iso_code, src_ip, traffic_direction, device_name, action, color, srcLatLng) {
    try{
        circleCount = circles.getLayers().length;
        circleArray = circles.getLayers();

        // Only allow 100 circles to be on the map at a time
        if (circleCount >= 100) {
            circles.removeLayer(circleArray[0]);
            circlesObject = {};
        }

        var key = srcLatLng.lat + "," + srcLatLng.lng;
        // Only draw circle if its coordinates are not already present in circlesObject
        if (!circlesObject[key]) {
            circlesObject[key] = L.circle(srcLatLng, 50000, {
                color: color,
                fillColor: color,
                fillOpacity: 0.2
            }).bindPopup(
                "<div class='row'>" +
                    "<div class='col-12 py-1'>" +
                        "<img src='/static/flags/" + iso_code + ".svg' width='26' height='18'>" + "<b> " + country +
                    "</div>" +
                    "<div class='col-3 text-muted'>" +
                        "<span>IPv4</span>" +
                    "</div>" +
                    "<div class='col-9'>" +
                        "<span>"+src_ip + "</span>" +
                    "</div>" +
                    "<div class='col-3 text-muted'>" +
                        "<span>Traffic</span>" +
                    "</div>" +
                    "<div class='col-9'>" +
                        "<span>"+traffic_direction + "</span>" +
                    "</div>" +
                    "<div class='col-3 text-muted'>" +
                        "<span>Device</span>" +
                    "</div>" +
                    "<div class='col-9'>" +
                        "<span>"+device_name + "</span>" +
                    "</div>" +
                    "<div class='col-3 text-muted'>" +
                        "<span>Action</span>" +
                    "</div>" +
                    "<div class='col-9'>" +
                        "<span>"+action + "</span>" +
                    "</div>" +
                "</div>"
            ).addTo(circles);
        }
    }
    catch(err) {
        console.log(err.message);
    }

}

var markersObject = {};

function addDestinationMarker(dst_country_name, dst_iso_code, dst_ip, dstLatLng) {
    try{
        markerCount = markers.getLayers().length;
        markerArray = markers.getLayers();

        // Only allow 50 markers to be on the map at a time
        if (markerCount >= 50) {
            markers.removeLayer(markerArray[0]);
            markersObject = {};
        }

        var key = dstLatLng.lat + "," + dstLatLng.lng;
        // Only draw marker if its coordinates are not already present in markersObject
        if (!markersObject[key]) {
            markersObject[key] = L.marker(dstLatLng, {
                icon: L.icon({
                    // svg color #E20074
                    iconUrl: '/static/images/marker.svg',
                    iconSize: [36, 36],
                    iconAnchor: [18, 36],
                    popupAnchor: [0, -36]
                }),
            }).bindPopup(
                "<div class='row'>" +
                    "<div class='col-12 py-1'>" +
                        "<img src='/static/flags/" + dst_iso_code + ".svg' width='26' height='18'>" + "<b> " + dst_country_name +
                    "</div>" +
                    "<div class='col-3 text-muted'>" +
                        "<span>IPv4</span>" +
                    "</div>" +
                    "<div class='col-9'>" +
                        "<span>"+dst_ip + "</span>" +
                    "</div>" +
                "</div>"
            ).addTo(markers);
        }
    }
    catch(err) {
        console.log(err.message);
    }

}

// Function to get flag URL based on ISO code
function getFlagUrl(isoCode) {
    return `/static/flags/${isoCode}.svg`;
}

function getVendorUrl(label) {
    return `/static/images/vendor/${label}.svg`;
}

// live threats table modal
const liveThreatsTableBody = document.querySelector('#liveThreatsTable tbody');

function addIncidentToTable(incident) {
    try{
        // Check if the modal is shown
        const liveModal = document.getElementById('liveModal');
        if (liveModal && liveModal.classList.contains('show')) {
            // Extract incident from the WebSocket message
            const scout = incident.ioc_scout;
            const cyberpot = incident.ioc_cyberpot || '-';
            const vendor_name = incident.ioc_vendor_name;
            const device = incident.ioc_device_name;
            const source = incident.ioc_source_ip;
            const destination = incident.ioc_destination_ip;
            const port = incident.ioc_destination_port;
            const protocol = incident.ioc_proto;
            const application = incident.ioc_application;
            const traffic = incident.ioc_traffic_direction;
            const action = incident.ioc_action;
            const srcCountry = incident.ioc_geo_lookup_metadata.source.country;
            const srcIsoCode = incident.ioc_geo_lookup_metadata.source.iso_code;
            const dstCountry = incident.ioc_geo_lookup_metadata.destination.country;
            const dstIsoCode = incident.ioc_geo_lookup_metadata.destination.iso_code;

            // Create a new table row
            const newRow = document.createElement('tr');
            newRow.innerHTML = `
                <td class="text-start">${scout}</td>
                <td class="text-start">${cyberpot}</td>
                <td class="text-start">
                    <img src="${getVendorUrl(vendor_name)}" alt="" style="width: 24px; height: auto;"> ${device}
                </td>
                <td class="text-start">${source}</td>
                <td class="text-start">${destination}</td>
                <td class="text-start">${protocol}/${port}</td>
                <td class="text-start">${application}</td>
                <td class="text-start">${traffic}</td>
                <td class="text-start">${action}</td>
                <td class="text-start">
                    <img src="${getFlagUrl(srcIsoCode)}" alt="" style="width: 24px; height: auto;"> ${srcCountry} 
                </td>
                <td class="text-start">
                    <img src="${getFlagUrl(dstIsoCode)}" alt="" style="width: 24px; height: auto;"> ${dstCountry}
                </td>
            `;

            // Prepend the new row to the table body
            liveThreatsTableBody.insertBefore(newRow, liveThreatsTableBody.firstChild);

            // Check the number of rows and remove the oldest if necessary
            if (liveThreatsTableBody.rows.length > MAX_INCIDENTS) {
                liveThreatsTableBody.deleteRow(-1); // Remove the last (oldest) row
            }

        }
    }
    catch(err) {
        console.log(err.message);
    }
}

// Incident main handler

const incidentHandlers = {
  ipv4: (incident) => {
    var srcLatLng = new L.LatLng(incident.ioc_geo_lookup_metadata.source.latitude, incident.ioc_geo_lookup_metadata.source.longitude,);
    var dstLatLng = new L.LatLng(incident.ioc_geo_lookup_metadata.destination.latitude, incident.ioc_geo_lookup_metadata.destination.longitude);
    var dstPoint = map.latLngToLayerPoint(dstLatLng);
    var srcPoint = map.latLngToLayerPoint(srcLatLng);

    Promise.all([
        addSourceCircle(incident.ioc_geo_lookup_metadata.source.country, incident.ioc_geo_lookup_metadata.source.iso_code, incident.ioc_source_ip, incident.ioc_traffic_direction, incident.ioc_device_name, incident.ioc_action, incident.ioc_application_color, srcLatLng),
        addDestinationMarker(incident.ioc_geo_lookup_metadata.destination.country, incident.ioc_geo_lookup_metadata.destination.iso_code, incident.ioc_destination_ip, dstLatLng),
        addIncidentToTable(incident),
        handleSourceParticle(incident.ioc_application_color, srcPoint),
        drawTrafficLine(incident.ioc_application_color, srcPoint, dstPoint, srcLatLng),
    ]).then(() => {
        // All operations have completed
    });
    
  },
  domain: (incident) => {},
  hash: (incident) => {},
  url: (incident) => {}
};

// For use within T-Pot:
//   - Access AttackMap via T-Pot's WebUI (https://<your T-Pot IP>:64297/map/)
//   - For Proxy_Pass to work we need to use wss:// instead of ws://
function connectWebSocket() {
  const WS_HOST = 'wss://'+window.location.host+window.map_websocket_channel_uri+'?wsskey='+window.wsskey;
  const webSock = new WebSocket(WS_HOST);

  webSock.onopen = function () {
    console.log('[*] WebSocket SSL connection established to channel: ' + window.map_websocket_channel_uri);
  };

  webSock.onclose = function (event) {
     var reason = "Unknown error reason?";
     if (event.code == 1000)     reason = "[ ] Endpoint terminating connection: Normal closure";
     else if(event.code == 1001) reason = "[ ] Endpoint terminating connection: Endpoint is \"going away\"";
     else if(event.code == 1002) reason = "[ ] Endpoint terminating connection: Protocol error";
     else if(event.code == 1003) reason = "[ ] Endpoint terminating connection: Unkonwn data";
     else if(event.code == 1004) reason = "[ ] Endpoint terminating connection: Reserved";
     else if(event.code == 1005) reason = "[ ] Endpoint terminating connection: No status code";
     else if(event.code == 1006) reason = "[ ] Endpoint terminating connection: Connection closed abnormally";
     else if(event.code == 1007) reason = "[ ] Endpoint terminating connection: Message was not consistent with the type of the message";
     else if(event.code == 1008) reason = "[ ] Endpoint terminating connection: Message \"violates policy\"";
     else if(event.code == 1009) reason = "[ ] Endpoint terminating connection: Message is too big";
     else if(event.code == 1010) reason = "[ ] Endpoint terminating connection: Client failed to negotiate ("+event.reason+")";
     else if(event.code == 1011) reason = "[ ] Endpoint terminating connection: Server encountered an unexpected condition";
     else if(event.code == 1015) reason = "[ ] Endpoint terminating connection: Connection closed due TLS handshake failure";
     else reason = "[ ] Endpoint terminating connection; Unknown reason";
     // Log error and display "T-Pot Honeypot Stats" title in red, so we know connection is interrupted
     console.log(reason+'. Attempting to reconnect ...');
     setTimeout(connectWebSocket, 5000); // Wait 5 seconds and attempt to reconnect
  };

  webSock.onmessage = function (e) {
    
    // parse incident
    var incident = JSON.parse(e.data);

    // console.log(incident);
    
    // define incident type and call related incidentHandlers function
    let handler = incidentHandlers[incident.ioc_type];

    // demonstrate incident
    if (handler) handler(incident);

  };
}

document.getElementById('dryrunButton').addEventListener('click', function() {
    
    swal({
        title: "Enable Dry Run Mode?",
        text: "This will allow you to test the map's functionality without actually submitting any data or making any changes.",
        icon: "warning",
        buttons: true,
        closeOnClickOutside: false,
        cancel: {
            text: "Cancel",
            value: null,
            visible: false,
            className: "",
            closeModal: true,
          },
          confirm: {
            text: "Yes, enable Dry Run",
            value: true,
            visible: true,
            className: "",
            closeModal: true
          }
      }).then((result) => {
        if (result) {
            // Enable Dry Run mode
            console.log("Dry Run mode enabled");
            // Add your logic here to enable Dry Run mode

            // change websocket channel
            window.map_websocket_channel_uri = "/socket/attackmap/dryrun"

            // reconnect websocket
            connectWebSocket();

        }
        else {
          // Proceed with actual action
          console.log("Proceeding with actual socket");
          // Add your logic here to proceed with the actual action
        }
      });

});

// Make the modal draggable
$("#liveModal .modal-dialog").draggable({
    handle: ".modal-content" // Allows dragging from header and footer
});

// Make the modal resizable
$("#liveModal .modal-content").resizable({
    minHeight: 150,  // Adjust to desired minimum height
    minWidth: 400,   // Adjust to desired minimum width
    handles: 'all',
    resize: function(event, ui) {
        // Adjust the modal-content height to match the new dialog size
        ui.element.find(".modal-content").height(ui.size.height - ui.element.find(".modal-header").outerHeight() - ui.element.find(".modal-footer").outerHeight());
    }
});

connectWebSocket();

