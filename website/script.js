document.addEventListener('DOMContentLoaded', () => {
    // -----------------------------------------------------------------
    // Part 1: Light / Dark Theme Toggle Logic
    // -----------------------------------------------------------------
    const themeToggleBtn = document.getElementById('theme-toggle');
    
    // Check localStorage or system preference for theme
    const savedTheme = localStorage.getItem('theme');
    const systemPrefersLight = window.matchMedia('(prefers-color-scheme: light)').matches;
    
    if (savedTheme === 'light' || (!savedTheme && systemPrefersLight)) {
        document.documentElement.setAttribute('data-theme', 'light');
    } else {
        document.documentElement.setAttribute('data-theme', 'dark'); // Default theme
    }

    if (themeToggleBtn) {
        themeToggleBtn.addEventListener('click', () => {
            const currentTheme = document.documentElement.getAttribute('data-theme');
            const newTheme = currentTheme === 'light' ? 'dark' : 'light';
            
            document.documentElement.setAttribute('data-theme', newTheme);
            localStorage.setItem('theme', newTheme);
        });
    }

    // -----------------------------------------------------------------
    // Part 2: Copy CLI Command to Clipboard Logic
    // -----------------------------------------------------------------
    const copyBtn = document.getElementById('btn-copy-command');
    if (copyBtn) {
        copyBtn.addEventListener('click', () => {
            const commandText = 'go run ./cmd/fire_starter -config config.json';
            navigator.clipboard.writeText(commandText).then(() => {
                const originalSVG = copyBtn.innerHTML;
                copyBtn.innerHTML = 'Copied! ✓';
                copyBtn.classList.add('copied');
                
                setTimeout(() => {
                    copyBtn.innerHTML = originalSVG;
                    copyBtn.classList.remove('copied');
                }, 2000);
            }).catch(err => {
                console.error('Failed to copy text: ', err);
            });
        });
    }
});