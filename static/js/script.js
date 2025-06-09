document.getElementById('transfer-form').addEventListener('submit', function (event) {
    document.getElementById('progress-container').style.display = 'block';
    let progressBar = document.getElementById('progress-bar');
    progressBar.style.width = '30%';
    progressBar.setAttribute('aria-valuenow', '30');

    // Giả lập tiến trình
    setTimeout(() => {
        progressBar.style.width = '60%';
        progressBar.setAttribute('aria-valuenow', '60');
    }, 1000);
    setTimeout(() => {
        progressBar.style.width = '100%';
        progressBar.setAttribute('aria-valuenow', '100');
    }, 2000);
});