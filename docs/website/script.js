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
    // Part 2: Modal Handling & Simulated Account Sign-Up / Log-In
    // -----------------------------------------------------------------
    const authModal = document.getElementById('auth-modal');
    const modalCloseBtn = document.getElementById('modal-close-btn');
    const modalFormState = document.getElementById('modal-form-state');
    const modalSuccessState = document.getElementById('modal-success-state');
    const modalForm = document.getElementById('simulated-signup-form');
    
    const signupTriggers = [
        document.getElementById('btn-signup-trigger'),
        document.getElementById('btn-hero-signup'),
        document.getElementById('btn-cta-signup')
    ];
    const loginTrigger = document.getElementById('btn-login-trigger');
    const modalToggleLink = document.getElementById('modal-toggle-link');
    
    let modalMode = 'signup'; // 'signup' or 'login'

    function openModal(mode = 'signup') {
        modalMode = mode;
        authModal.classList.add('active');
        modalFormState.style.display = 'block';
        modalSuccessState.style.display = 'none';
        
        const title = document.getElementById('modal-title');
        const subtitle = document.getElementById('modal-subtitle');
        const nameField = document.getElementById('field-name-container');
        const companyField = document.getElementById('field-company-container');
        const submitBtn = document.getElementById('btn-submit-signup');
        const toggleText = document.getElementById('modal-toggle-text');
        
        if (mode === 'signup') {
            title.innerText = 'Create an Account';
            subtitle.innerText = 'Start running continuous security scans inside your environments.';
            nameField.style.display = 'flex';
            companyField.style.display = 'flex';
            submitBtn.innerText = 'Create Free Account';
            toggleText.innerText = 'Already have an account?';
            modalToggleLink.innerText = 'Log In';
        } else {
            title.innerText = 'Welcome Back';
            subtitle.innerText = 'Log in to your Fire Starter dashboard.';
            nameField.style.display = 'none';
            companyField.style.display = 'none';
            submitBtn.innerText = 'Log In';
            toggleText.innerText = 'New to Fire Starter?';
            modalToggleLink.innerText = 'Sign Up';
        }
    }

    function closeModal() {
        authModal.classList.remove('active');
    }

    // Assign triggers
    signupTriggers.forEach(btn => {
        if (btn) btn.addEventListener('click', () => openModal('signup'));
    });
    if (loginTrigger) {
        loginTrigger.addEventListener('click', () => openModal('login'));
    }
    if (modalCloseBtn) {
        modalCloseBtn.addEventListener('click', closeModal);
    }
    
    // Close modal on background click
    authModal.addEventListener('click', (e) => {
        if (e.target === authModal) closeModal();
    });

    // Toggle Link between login / signup modes
    if (modalToggleLink) {
        modalToggleLink.addEventListener('click', (e) => {
            e.preventDefault();
            openModal(modalMode === 'signup' ? 'login' : 'signup');
        });
    }

    // Submit Simulated Form
    if (modalForm) {
        modalForm.addEventListener('submit', (e) => {
            e.preventDefault();
            const submitBtn = document.getElementById('btn-submit-signup');
            const originalText = submitBtn.innerText;
            
            // Show loading animation on button
            submitBtn.disabled = true;
            submitBtn.innerText = modalMode === 'signup' ? 'Creating Account...' : 'Logging In...';
            
            setTimeout(() => {
                submitBtn.disabled = false;
                submitBtn.innerText = originalText;
                
                // Transition to success state
                modalFormState.style.display = 'none';
                modalSuccessState.style.display = 'flex';
                
                const successTitle = modalSuccessState.querySelector('.success-title');
                const successText = modalSuccessState.querySelector('.success-text');
                
                if (modalMode === 'signup') {
                    successTitle.innerText = 'Account Created!';
                    successText.innerText = 'Normally, this would redirect you to the SaaS console dashboard. For this developer trial, check out our CLI execution steps and deployment docs on GitHub to start scanning targets!';
                } else {
                    successTitle.innerText = 'Login Successful!';
                    successText.innerText = 'Welcome back! You have successfully authenticated. Usually, you\'d access your persistent team scans here. For the trial, click below to see our implementation guides on GitHub!';
                }
            }, 1200);
        });
    }
});