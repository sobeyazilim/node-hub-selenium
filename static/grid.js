
// Select all containers with the class container-grid
const gridContainers = document.querySelectorAll('.container-grid');

// Loop through each container
gridContainers.forEach((container) => {

    // Select the search input and filter buttons within the current container
    const searchInput = container.querySelector('.search-input');
    const filterButtons = container.querySelectorAll('.nav-tabs-filterby button');
    const clearButton = container.querySelector('button.btn-search-clear');

    // Select the clear button
    // const clearButton = searchInput.nextElementSibling;

    // Store the current filter type
    let currentFilterType = 'all';

    // Add event listener to the search input
    if (searchInput){
        searchInput.addEventListener('input', () => {
            applySearchAndFilter(container, currentFilterType);
        });
    }
    // Add event listener to the clear button
    if (clearButton){
        clearButton.addEventListener('click', (e) => {
            e.preventDefault();
            searchInput.value = '';
            searchInput.focus();
            applySearchAndFilter(container, currentFilterType);
        });
    }

    // Add event listeners to the filter buttons
    filterButtons.forEach((button) => {
        button.addEventListener('click', () => {
        currentFilterType = button.textContent.toLowerCase();
        applySearchAndFilter(container, currentFilterType);
        });
    });
    
});

// Function to apply search and filter
function applySearchAndFilter(container, type) {

    // Select the content items within the current container
    const tableContentItems = container.querySelectorAll('.content-item-table');
    const gridContentItems = container.querySelectorAll('.content-item-grid');

    // Get the search value
    const searchValue = container.querySelector('.search-input').value.toLowerCase();

    // Loop through each content item in the table view
    tableContentItems.forEach((item) => {

        if (!searchValue && type === 'all'){
            item.classList.remove('d-none');
        }else {

            // Get the item's type and search attributes
            const itemType = item.getAttribute('data-type');
            const searchAttribute = item.getAttribute('data-search');

            // Check if the item matches the search value and filter type
            const matchesSearch = !searchValue || (searchAttribute && searchAttribute.toLowerCase().includes(searchValue));
            const matchesFilter = (type === 'all') || (itemType === type);

            // Show or hide the item based on the search and filter conditions
            if (matchesSearch && matchesFilter) {
                item.classList.remove('d-none');
            } else {
                item.classList.add('d-none');
            }
        }
    });

    // Loop through each content item in the grid view
    gridContentItems.forEach((item) => {
        if (!searchValue && type === 'all'){
            item.classList.remove('d-none');
        }else {
            // Get the item's type and search attributes
            const itemType = item.getAttribute('data-type');
            const searchAttribute = item.getAttribute('data-search');

            // Check if the item matches the search value and filter type
            const matchesSearch = !searchValue || (searchAttribute && searchAttribute.toLowerCase().includes(searchValue));
            const matchesFilter = (type === 'all') || (itemType === type);

            // Show or hide the item based on the search and filter conditions
            if (matchesSearch && matchesFilter) {
                item.classList.remove('d-none');
            } else {
                item.classList.add('d-none');
            }
        }
    });
}