document.addEventListener('DOMContentLoaded', () => {
    // Fetch data from the /cves/list endpoint
    fetch('/cves/list')
        .then(response => {
            // Check if the response is okay
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            // Find the table body in the DOM
            const tableBody = document.querySelector('#cve-table tbody');
            
            if (!tableBody) {
                console.error('Table body not found in the DOM');
                return;
            }

            // Populate table with CVE data
            data.forEach(cve => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${cve.cve_id || 'N/A'}</td>
                    <td>${cve.description || 'N/A'}</td>
                    <td>${cve.base_score || 'N/A'}</td>
                    <td>${cve.last_modified || 'N/A'}</td>
                `;
                tableBody.appendChild(row);
            });

            // Display a message if no CVEs are available
            if (data.length === 0) {
                const noDataRow = document.createElement('tr');
                noDataRow.innerHTML = `
                    <td colspan="4">No CVEs available to display.</td>
                `;
                tableBody.appendChild(noDataRow);
            }
        })
        .catch(error => {
            console.error('Error fetching CVE data:', error);

            // Display error message in the table
            const tableBody = document.querySelector('#cve-table tbody');
            if (tableBody) {
                const errorRow = document.createElement('tr');
                errorRow.innerHTML = `
                    <td colspan="4">An error occurred while fetching CVE data. Please try again later.</td>
                `;
                tableBody.appendChild(errorRow);
            }
        });
});
