
$(document).ready(function() {

    // Enable tooltips everywhere
    $('[data-bs-toggle="tooltip"]').tooltip();
    $('[data-bs-tooltip="tooltip"]').tooltip();

    // Enable popovers everywhere
    const popoverTriggerList = document.querySelectorAll('[data-bs-toggle="popover"]')
    const popoverList = [...popoverTriggerList].map(popoverTriggerEl => new bootstrap.Popover(popoverTriggerEl))

    // Render select2 form inputs
    $('.select2-box-single:not(.search-enabled)').select2({
        theme: 'bootstrap-5', // Apply Bootstrap 5 theme to Select2
        placeholder: '',
        allowClear: true,
        closeOnSelect: true,
    });

    $('.select2-box-single.search-enabled').select2({
        theme: 'bootstrap-5', // Apply Bootstrap 5 theme to Select2
        placeholder: '',
        allowClear: true,
        closeOnSelect: true,
        dropdownCssClass: 'search-enabled'
    });


    $('.select2-box-multiple:not(.search-enabled)').select2({
        theme: 'bootstrap-5', // Apply Bootstrap 5 theme to Select2
        placeholder: '',
        allowClear: false,
        closeOnSelect: false,
        scrollAfterSelect: true,
    });
    
    $('.select2-box-multiple.search-enabled').select2({
        theme: 'bootstrap-5', // Apply Bootstrap 5 theme to Select2
        placeholder: '',
        allowClear: false,
        closeOnSelect: false,
        scrollAfterSelect: true,
        dropdownCssClass: 'search-enabled',
    });

    // open closest select2
    const openClosestSelect2Buttons = document.querySelectorAll('.open-closest-select2');

    // Check if any buttons exist before adding event listeners
    if (openClosestSelect2Buttons.length > 0) {
        // Iterate over each button and add an event listener
        openClosestSelect2Buttons.forEach(button => {
            button.addEventListener('click', function() {
                // Find the closest <select> element
                const closestSelect = button.closest('.input-group').querySelector('select');

                // Open the Select2 dropdown for the closest <select>
                $(closestSelect).select2('open');

            });
        });
    }


    // toggle closest password input
    const togglePasswordButtons = document.querySelectorAll('.toggle-closest-password');

    // Check if any buttons exist before adding event listeners
    if (togglePasswordButtons.length > 0) {

        togglePasswordButtons.forEach(function (toggleButton) {
            toggleButton.addEventListener('click', function () {
                // Find the closest password input
                const passwordInput = toggleButton.closest('.input-group').querySelector('input[type="password"], input[type="text"]');

                if (passwordInput) {
                    // Toggle the input type
                    const isPassword = passwordInput.getAttribute('type') === 'password';
                    const newType = isPassword ? 'text' : 'password';
                    passwordInput.setAttribute('type', newType);

                    // Change the icon based on the input type
                    const icon = isPassword ? 'bx-hide' : 'bx-show';
                    toggleButton.querySelector('i').className = `bx ${icon} fs-5`;
                }
            });
        });

    }

    const togglePasswordLoginButtons = document.querySelectorAll('.toggle-closest-password-login');

    // Check if any buttons exist before adding event listeners
    if (togglePasswordLoginButtons.length > 0) {

        togglePasswordLoginButtons.forEach(function (toggleButton) {
            toggleButton.addEventListener('click', function () {
                // Find the closest password input
                const passwordInput = toggleButton.closest('.input-group').querySelector('input[type="password"], input[type="text"]');

                if (passwordInput) {
                    // Toggle the input type
                    const isPassword = passwordInput.getAttribute('type') === 'password';
                    const newType = isPassword ? 'text' : 'password';
                    passwordInput.setAttribute('type', newType);

                    // Change the icon based on the input type
                    const icon = isPassword ? 'bx-hide' : 'bx-show';
                    toggleButton.querySelector('i').className = `bx ${icon} fs-5`;
                }
            });
        });

    }

    // edit form post preloader enable
    const formsPreloaderEnabled = document.querySelectorAll('.form-preloder-enabled');

    if (formsPreloaderEnabled.length > 0) {
        
        formsPreloaderEnabled.forEach(function (preform) {

            // Function to show preloader on form submission
            preform.addEventListener('submit', function(event) {
                // Show preloader
                document.documentElement.setAttribute("data-preloader", "enable");
                // Optionally, prevent default form submission for demonstration
                // event.preventDefault();
            
            });

        });
    
    }


    $('div.page-tabs-menu > a').on('click', function(e) {
        e.preventDefault();
        $(this).tab('show');
    });

    // Handle preloader visibility when the page becomes visible
    document.addEventListener('visibilitychange', function() {
        if (document.visibilityState === 'visible') {
            setTimeout(function () {
                document.documentElement.setAttribute("data-preloader", "disable");
            }, 1000);
        }
    });


    // show preloader when click
    const menuItems = document.getElementsByClassName('menuitem');

    for (let i = 0; i < menuItems.length; i++) {
        menuItems[i].addEventListener('click', function() {
            // Show preloader
            document.documentElement.setAttribute("data-preloader", "enable");
        });
    }
});


document.addEventListener("DOMContentLoaded", function() {

    // flatpickr calendar-time render
    $("input.flatpickr-calendar-time").flatpickr({
        dateFormat: "Y-m-d H:i",
        // defaultDate: new Date().fp_incr(1), // Set the default date to the current date and time
        minDate: "today",
        maxDate: new Date().fp_incr(365), // 1 year from now
        enableTime: true,
        allowInput: false,
    });

    // flatpickr calendar-time-inline render
    $("input.flatpickr-calendar-time-inline").flatpickr({
        dateFormat: "Y-m-d H:i",
        // defaultDate: new Date().fp_incr(1), // Set the default date to the current date and time
        minDate: "today",
        maxDate: new Date().fp_incr(365), // 1 year from now
        enableTime: true,
        allowInput: false,
        inline: true,
    });

    // flatpickr only calendar render
    $("input.flatpickr-only-calendar").flatpickr({
        dateFormat: "Y-m-d",
        // defaultDate: new Date().fp_incr(1), // Set the default date to the current date and time
        minDate: "today",
        maxDate: new Date().fp_incr(365), // 1 year from now
        enableTime: false,
        allowInput: false,
    });

    // flatpickr only calendar-inline render
    $("input.flatpickr-only-calendar-inline").flatpickr({
        dateFormat: "Y-m-d",
        // defaultDate: new Date().fp_incr(1), // Set the default date to the current date and time
        minDate: "today",
        maxDate: new Date().fp_incr(365), // 1 year from now
        enableTime: false,
        allowInput: false,
        inline: true,
    });

    // flatpickr only time render
    $("input.flatpickr-only-time").flatpickr({
        dateFormat: "H:i",
        // defaultDate: new Date(), // Set the default date to the current date and time
        enableTime: true,
        noCalendar: true,
        time_24hr: true,
        allowInput: false,
    });

    // flatpickr only time render
    $("input.flatpickr-only-time-inline").flatpickr({
        dateFormat: "H:i",
        // defaultDate: new Date(), // Set the default date to the current date and time
        enableTime: true,
        noCalendar: true,
        time_24hr: true,
        allowInput: false,
        inline: true,
    });


    // flatpickr range calendar render
    $("input.flatpickr-range-calendar").flatpickr({
        mode: "range",
        dateFormat: "Y-m-d",
        // defaultDate: [new Date(), new Date().fp_incr(1)], // Set default dates to today and tomorrow
        minDate: "today",
        maxDate: new Date().fp_incr(365), // 1 year from now
        enableTime: false,
        allowInput: false,
    });

    // flatpickr range calendar-inline render
    $("input.flatpickr-range-calendar-inline").flatpickr({
        mode: "range",
        dateFormat: "Y-m-d",
        // defaultDate: [new Date(), new Date().fp_incr(1)], // Set default dates to today and tomorrow
        minDate: "today",
        maxDate: new Date().fp_incr(365), // 1 year from now
        enableTime: false,
        allowInput: false,
        inline: true,
    });

});


// preloader disable
// Hide preloader when page is fully loaded
window.onload = function () {

    setTimeout(function () {
        document.documentElement.setAttribute("data-preloader", "disable");
    }, 500);

};

function updateSidebarSize() {
    const htmlTag = document.documentElement; // This refers to the <html> element
    if (window.innerWidth <= 767.98) {
        htmlTag.setAttribute('data-sidebar-size', 'sm');
    } else {
        htmlTag.removeAttribute('data-sidebar-size');
    }
}

// Function to toggle the sidebar menu
function toggleSidebar() {
    const navbarMenu = document.querySelector('.navbar-menu'); // Get the navbar menu element

    if (navbarMenu) {
        // Check if the navbarMenu has the sidebar-visible class
        if (navbarMenu.classList.contains('sidebar-visible')) {
            // If the sidebar is currently visible, hide it
            navbarMenu.classList.remove('sidebar-visible'); // Remove class to hide the sidebar
        } else {
            // If the sidebar is currently hidden, show it
            navbarMenu.classList.add('sidebar-visible'); // Add class to show the sidebar
        }
    }
}

// Function to close the sidebar when the overlay is clicked
function closeSidebar() {
    const htmlTag = document.documentElement;
    const navbarMenu = document.querySelector('.navbar-menu'); // Get the navbar menu element

    htmlTag.setAttribute('data-sidebar-size', 'sm'); // Set to small
    navbarMenu.classList.remove('sidebar-visible'); // Remove class to hide the sidebar
}

// Initial check
window.addEventListener('DOMContentLoaded', () => {
    updateSidebarSize();

    // Check if the sidebar switcher exists before adding the event listener
    const sidebarSwitcher = document.querySelector('.sidebar-switcher');
    if (sidebarSwitcher) {
        sidebarSwitcher.addEventListener('click', toggleSidebar);
    }

    // Add click event to the overlay to close the sidebar
    const sidebarOverlay = document.querySelector('.sidebar-overlay');
    if (sidebarOverlay) {
        sidebarOverlay.addEventListener('click', closeSidebar);
    }

    // Add click event to the overlay update
    const sidebarOverlayUpdate = document.querySelector('.sidebar-overlay-update');
    if (sidebarOverlayUpdate) {
        sidebarOverlayUpdate.addEventListener('click', function() {
            toastr.info('Use "Return" button to back to menu.');
        });
    }

});

// Add event listener for resize
window.addEventListener('resize', updateSidebarSize);


// Load the user's theme preference from localStorage
document.addEventListener('DOMContentLoaded', () => {
    
    const currentTheme = localStorage.getItem('app-theme');
    
    if (currentTheme) {
        document.documentElement.setAttribute('data-theme', currentTheme); // Set data-theme on <html>
    } else {
        // Default theme
        document.documentElement.setAttribute('data-theme', 'dark');
    }

});

// Form input spin is used to increase and decrease the number
document.addEventListener('DOMContentLoaded', () => {
    const plusButtons = document.querySelectorAll('.step-plus');
    const minusButtons = document.querySelectorAll('.step-minus');

    // Add click event to all 'plus' buttons
    plusButtons.forEach((button) => {
        button.addEventListener('click', () => {
            const input = button.previousElementSibling;
            const max = parseInt(input.getAttribute('max'), 10) || Infinity;
            let value = parseInt(input.value, 10) || 0;

            if (value < max) {
                input.value = value + 1;
            }
        });
    });

    // Add click event to all 'minus' buttons
    minusButtons.forEach((button) => {
        button.addEventListener('click', () => {
            const input = button.nextElementSibling;
            const min = parseInt(input.getAttribute('min'), 10) || -Infinity;
            let value = parseInt(input.value, 10) || 0;

            if (value > min) {
                input.value = value - 1;
            }
        });
    });
});