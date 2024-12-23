(function () {
    "use strict";

    L.Control._Tools = L.Control.Zoom.extend({
        options: {
            position: 'topright',
            resetTitle: 'Reset Zoom',
            zoomInTitle: 'Zoom in',
            zoomOutTitle: 'Zoom out',
            layerTitle: 'Layers',
            widgetThreatTitle: 'Threats Widget',
            fullscreenTitle: 'Fullscreen',
            fullscreenExitTitle: 'Exit Fullscreen',
            fullscreenIcon: '<i class="bx bx-fullscreen fs-3"></i>',
            fullscreenExitIcon: '<i class="bx bx-exit-fullscreen fs-3"></i>',
            homeCoordinates: null,
            homeZoom: null,
        },

        onAdd: function (map) {
            var controlName = 'leaflet-control-tools',
                container = L.DomUtil.create('div', controlName + ' leaflet-bar'),
                options = this.options;

            if (options.homeCoordinates === null) {
                options.homeCoordinates = map.getCenter();
            }
            if (options.homeZoom === null) {
                options.homeZoom = map.getZoom();
            }

            // Fullscreen button
            this._fullscreenButton = this._createButton(
                this.options.fullscreenIcon,
                this.options.fullscreenTitle,
                'fullscreen map-control-buttons control-button-first d-flex align-items-center justify-content-center bg-dark text-white',
                container,
                this._toggleFullscreen.bind(this)
            );

            // Zoom In button
            var zoomInText = '<i class="bx bx-plus fs-3"></i>';
            this._zoomInButton = this._createButton(
                zoomInText,
                this.options.zoomInTitle,
                'zoom-in map-control-buttons d-flex align-items-center justify-content-center bg-dark text-white',
                container,
                this._zoomIn.bind(this)
            );

            // Zoom Out button
            var zoomOutText = '<i class="bx bx-minus fs-3"></i>';
            this._zoomOutButton = this._createButton(
                zoomOutText,
                this.options.zoomOutTitle,
                'zoom-out map-control-buttons d-flex align-items-center justify-content-center bg-dark text-white',
                container,
                this._zoomOut.bind(this)
            );

            // Reset Zoom button
            var resetText = '<i class="bx bx-reset fs-3"></i>';
            this._zoomHomeButton = this._createButton(
                resetText,
                this.options.resetTitle,
                'zoom-reset map-control-buttons d-flex align-items-center justify-content-center bg-dark text-white',
                container,
                this._zoomHome.bind(this)
            );

            // Layer button
            var layerText = '<i class="bx bx-map-alt fs-3"></i>';
            this._layerButton = this._createButton(
                layerText,
                this.options.layerTitle,
                'layer map-control-buttons d-flex align-items-center justify-content-center bg-dark text-white mt-2',
                container,
                this._openLayerOffcanvas.bind(this)
            );

            // Widget Threats button
            var widgetThreatText = '<i class="bx bxs-bug-alt fs-3"></i>';
            this._widgetThreatButton = this._createButton(
                widgetThreatText,
                this.options.widgetThreatTitle,
                'widget-threat map-control-buttons d-flex control-button-last align-items-center justify-content-center bg-dark text-white',
                container,
                this._openLiveModal.bind(this) // Bind the modal opening function
            );

            // Initialize tooltips for the buttons
            this._initializeTooltips(container);

            // Populate Offcanvas with layer options
            this._populateLayerOptions();

            this._updateDisabled();
            map.on('zoomend zoomlevelschange', this._updateDisabled, this);
            window.addEventListener('resize', this._updateFullscreenIcon.bind(this));

            return container;
        },

        _createButton(html, title, className, container, onClick) {
            var button = L.DomUtil.create('a', className, container);
            button.innerHTML = html;
            button.href = '#';
            button.title = title;
            button.setAttribute('data-bs-toggle', 'tooltip');
            button.setAttribute('data-bs-placement', 'left');
            button.setAttribute('data-bs-trigger', 'hover');            

            L.DomEvent.on(button, 'click', L.DomEvent.stopPropagation)
                .on(button, 'click', L.DomEvent.preventDefault)
                .on(button, 'click', onClick);
            return button;
        },

        _initializeTooltips(container) {
            // Initialize all tooltips within the container
            var tooltipTriggerList = [].slice.call(container.querySelectorAll('[data-bs-toggle="tooltip"]'));
            tooltipTriggerList.forEach(function (tooltipTriggerEl) {
                new bootstrap.Tooltip(tooltipTriggerEl);
            });
        },

        setHomeBounds: function (bounds) {
            if (bounds === undefined) {
                bounds = this._map.getBounds();
            } else {
                if (typeof bounds.getCenter !== 'function') {
                    bounds = L.latLngBounds(bounds);
                }
            }
            this.options.homeZoom = this._map.getBoundsZoom(bounds);
            this.options.homeCoordinates = bounds.getCenter();
        },

        setHomeCoordinates: function (coordinates) {
            if (coordinates === undefined) {
                coordinates = this._map.getCenter();
            }
            this.options.homeCoordinates = coordinates;
        },

        setHomeZoom: function (zoom) {
            if (zoom === undefined) {
                zoom = this._map.getZoom();
            }
            this.options.homeZoom = zoom;
        },

        getHomeZoom: function () {
            return this.options.homeZoom;
        },

        getHomeCoordinates: function () {
            return this.options.homeCoordinates;
        },

        _zoomHome: function (e) {
            this._map.setView(this.options.homeCoordinates, this.options.homeZoom);
        },

        _toggleFullscreen: function () {
            if (!document.fullscreenElement) {
                if (this._map.getContainer().requestFullscreen) {
                    this._map.getContainer().requestFullscreen();
                } else if (this._map.getContainer().mozRequestFullScreen) { // Firefox
                    this._map.getContainer().mozRequestFullScreen();
                } else if (this._map.getContainer().webkitRequestFullscreen) { // Chrome, Safari and Opera
                    this._map.getContainer().webkitRequestFullscreen();
                } else if (this._map.getContainer().msRequestFullscreen) { // IE/Edge
                    this._map.getContainer().msRequestFullscreen();
                }
            } else {
                if (document.exitFullscreen) {
                    document.exitFullscreen();
                } else if (document.mozCancelFullScreen) { // Firefox
                    document.mozCancelFullScreen();
                } else if (document.webkitExitFullscreen) { // Chrome, Safari and Opera
                    document.webkitExitFullscreen();
                } else if (document.msExitFullscreen) { // IE/Edge
                    document.msExitFullscreen();
                }
            }
        },

        _updateFullscreenIcon: function () {
            var container = document.querySelector('.leaflet-control-container');
            if (document.fullscreenElement) {
                this._fullscreenButton.innerHTML = this.options.fullscreenExitIcon;
                this._fullscreenButton.title = this.options.fullscreenExitTitle;
                container.classList.add('fullscreen');
                // this._layerButton.classList.add('d-none');
                // this._widgetThreatButton.classList.add('d-none');

                $('#liveModal').css({
                    'left': '',
                    'top': ''
                });
                $('#liveModal .modal-dialog').css({
                    'left': '',
                    'top': ''
                });

                $("#brandLogo").prependTo("#map");
                $("#liveModal").appendTo("#map");
                $("#layerOffcanvas").appendTo("#map");
                


            } else {
                this._fullscreenButton.innerHTML = this.options.fullscreenIcon;
                this._fullscreenButton.title = this.options.fullscreenTitle;
                container.classList.remove('fullscreen');
                // this._layerButton.classList.remove('d-none');
                // this._widgetThreatButton.classList.remove('d-none');

                $('#liveModal').css({
                    'left': '',
                    'top': ''
                });
                $('#liveModal .modal-dialog').css({
                    'left': '',
                    'top': ''
                });

                $("#map #liveModal").appendTo("body");
                $("#map #layerOffcanvas").appendTo("body");
                $("#map #brandLogo").prependTo("#nav-leftbar");

            }
        },

        _openLayerOffcanvas: function () {
            var layerOffcanvas = new bootstrap.Offcanvas(document.getElementById('layerOffcanvas'));
            layerOffcanvas.show();
        },

        _openLiveModal: function() {
            // Trigger the modal using jQuery or vanilla JS
            $('#liveModal').modal('show'); // If using jQuery
        },

        _populateLayerOptions: function () {
            var layerForm = document.getElementById('layerSelectionForm');
        
            // Clear existing options
            layerForm.innerHTML = '';
        
            var gridContainer = document.createElement('div');
            gridContainer.className = 'd-grid gap-3 p-3';
        
            for (var key in tileLayers) {
                if (tileLayers.hasOwnProperty(key)) {
                    var layerItem = document.createElement('div');
                    layerItem.className = 'position-relative h-100px';
        
                    var radio = document.createElement('input');
                    radio.className = 'btn-check';
                    radio.type = 'radio';
                    radio.name = 'layerOptions';
                    radio.id = key;
                    radio.value = key;

                    // Check the radio button if it's the default layer
                    if (key === "Transport Map") {
                        radio.checked = true;
                    }

                    var label = document.createElement('label');
                    label.className = 'btn btn-outline-light border-1 rounded-3 bg-transparent position-absolute p-0 h-100 w-100 overflow-hidden';
                    label.htmlFor = key;
        
                    // Add background image to badge using the layerImages mapping
                    var imageUrl = '/static/images/maps/' + tileLayersImages[key];
                    label.style.backgroundImage = 'url("' + imageUrl + '")';
                    label.style.backgroundSize = 'cover';
                    label.style.backgroundPosition = 'center';
                    // label.style.height = '100px'; // Adjust height as needed
                    // label.style.width = '100px'; // Adjust width as needed

                    var badge = document.createElement('span');
                    badge.className = 'badge position-absolute top-0 start-0 rounded-top-0 rounded-start-0 py-1 px-2 bg-light bg-opacity-75 text-dark text-wrap text-start fs-6 lh-base';
                    badge.textContent = key;

                    label.appendChild(badge);
                    layerItem.appendChild(radio);
                    layerItem.appendChild(label);
                    gridContainer.appendChild(layerItem);
                }
            }
        
            layerForm.appendChild(gridContainer);
            layerForm.addEventListener('change', this._handleLayerSelection.bind(this));
        },
        _handleLayerSelection: function () {
            // Get the selected layer ID from the radio button input
            var selectedLayerId = document.querySelector('input[name="layerOptions"]:checked').value;
            
            // Get the selected layer based on the selectedLayerId
            var selectedLayer = tileLayers[selectedLayerId];
            
            // Check if the selected layer exists
            if (!selectedLayer) {
                console.error("Selected layer is not defined:", selectedLayerId);
                return;
            }
        
            // Remove the current layer if it exists
            if (this._currentLayer) {
                this._map.removeLayer(this._currentLayer);
            }

            // Get the current zoom level of the map
            var currentZoom = this._map.getZoom();
            
            // Determine the URL to use based on the zoom level
            let mapMaxZoom;
            var tileLayerUrl;

            if (map_switched_type == 'online') {
                tileLayerUrl = mapUrls[selectedLayerId].online;
                mapMaxZoom = onlineZoomMax;
                console.log("Switched online maps mode:" , selectedLayer.options.attribution);
            } else {
                tileLayerUrl = mapUrls[selectedLayerId].offline;
                mapMaxZoom = offlineZoomMax;
                console.log("Switched offline maps mode: ", selectedLayer.options.attribution);
            }

            // Check if the tileLayerUrl is valid
            if (!tileLayerUrl) {
                console.error("Tile layer URL is not defined for:", selectedLayerId);
                return;
            }
        
            // Create a new tile layer with the selected URL
            var tileLayerOptions = {
                attribution: selectedLayer.options.attribution,
                detectRetina: true,
                subdomains: 'abc',
                tileSize: 256
            };
        
            var newTileLayer = createTileLayer(tileLayerUrl, tileLayerOptions);
        
            // Set max zoom for online and offline maps
            this._map.setMaxZoom(mapMaxZoom);
            
            // Update the _currentLayer and add the new layer to the map
            this._currentLayer = newTileLayer;

            this._currentLayer.addTo(this._map);
        }
    });

    L.Control.Tools = function (options) {
        return new L.Control._Tools(options);
    };
}());
