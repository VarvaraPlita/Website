document.addEventListener('DOMContentLoaded', (event) => {
    const toggleDarkMode = document.querySelector('.btn-dark-mode');
    const body = document.body;
    const greyElement = document.querySelector('.grey-element');
    const header = document.querySelector('.header');

    toggleDarkMode.addEventListener('click', () => {
        body.classList.toggle('dark-mode');
        if (body.classList.contains('dark-mode')) {
            toggleDarkMode.innerHTML = '<img src="/static/img/sun.png" alt="Light Mode" style="width: 20px; height: 20px;">';
            if (greyElement) {
                greyElement.style.backgroundColor = '#1f1f1f';
                greyElement.style.color = '#e0e0e0';
            }
            if (header) {
                header.style.backgroundColor = '#1f1f1f';
                header.style.color = '#e0e0e0';
            }
            toggleDarkMode.style.backgroundColor = '#333';
            toggleDarkMode.style.border = '1px solid #555';
            toggleDarkMode.style.color = '#e0e0e0';
            toggleDarkMode.querySelector('img').style.filter = 'invert(0%)';
        } else {
            toggleDarkMode.innerHTML = '<img src="/static/img/moon.png" alt="Dark Mode" style="width: 20px; height: 20px;">';
            if (greyElement) {
                greyElement.style.backgroundColor = '#f8f9fa';
                greyElement.style.color = '#333';
            }
            if (header) {
                header.style.backgroundColor = '#f8f9fa';
                header.style.color = '#333';
            }
            toggleDarkMode.style.backgroundColor = '#fff';
            toggleDarkMode.style.border = '1px solid #ccc';
            toggleDarkMode.style.color = '#333';
            toggleDarkMode.querySelector('img').style.filter = 'invert(100%)';
        }
    });
});
