/**
 * PhishGuard Tooltip Engine
 *
 * Lightweight tooltip system for security term explanations.
 * Reads data-tip attributes and shows popovers on hover/focus.
 */
(function () {
    'use strict';

    var TERMS = {
        'SPF': 'Sender Policy Framework \u2014 checks if the sending mail server is authorized by the sender\'s domain to send email on its behalf. A "pass" means the server is legitimate.',
        'DKIM': 'DomainKeys Identified Mail \u2014 a cryptographic signature in the email header that proves the message was not altered in transit. A "pass" confirms message integrity.',
        'DMARC': 'Domain-based Message Authentication, Reporting & Conformance \u2014 a policy set by the sender\'s domain that tells receiving servers what to do when SPF or DKIM checks fail.',
        'Threat Score': 'A composite risk score from 0 to 100 calculated from multiple analysis dimensions. Higher scores indicate a greater likelihood of phishing or malicious intent.',
        'IOC': 'Indicator of Compromise \u2014 an observable artifact such as an IP address, domain, file hash, or URL that suggests a system may have been compromised or targeted.',
        'MITRE ATT&CK': 'A globally-accessible knowledge base of adversary tactics and techniques based on real-world observations, maintained by MITRE Corporation. Used to classify attack behaviors.',
        'YARA': 'A pattern-matching tool used to identify and classify malware by scanning files for specific byte sequences, strings, or conditions defined in YARA rules.',
        'ML Classification': 'Machine Learning Classification \u2014 an automated model trained to distinguish phishing emails from legitimate ones based on statistical patterns across multiple features.',
        'NLP Analysis': 'Natural Language Processing \u2014 analyzes the text of the email body for urgency cues, threat language, impersonation patterns, and social engineering techniques.',
        'Homoglyph': 'A character that looks visually similar to another (e.g., using a zero "0" instead of the letter "O"). Attackers use these to create deceptive domain names.',
        'Credential Harvesting': 'A phishing technique where attackers create fake login pages to steal usernames and passwords when victims enter their credentials.',
        'Browser Detonation': 'Safely rendering a URL in a sandboxed headless browser to detect JavaScript redirects, credential forms, iframes, and other dynamic threats.',
        'Social Engineering': 'Psychological manipulation techniques used to trick people into divulging sensitive information or performing actions that compromise security.',
        'Reply-To Mismatch': 'When the Reply-To address differs from the From address, it may indicate the sender wants responses sent to a different (potentially malicious) inbox.',
        'Threat Intelligence': 'Data collected from security feeds and databases (AbuseIPDB, PhishTank, VirusTotal, etc.) about known malicious IPs, domains, and file hashes.',
        'STIX': 'Structured Threat Information Expression \u2014 a standardized language for describing cyber threat information so it can be shared and consumed across security tools.',
    };

    var activeTooltip = null;

    function createTooltip(el) {
        var key = el.getAttribute('data-tip');
        var text = TERMS[key] || key;

        var tip = document.createElement('div');
        tip.className = 'pg-tooltip';
        tip.textContent = text;

        document.body.appendChild(tip);

        var rect = el.getBoundingClientRect();
        var tipRect = tip.getBoundingClientRect();
        var left = rect.left + rect.width / 2 - tipRect.width / 2;
        var top = rect.top - tipRect.height - 8;

        if (left < 8) left = 8;
        if (left + tipRect.width > window.innerWidth - 8) left = window.innerWidth - tipRect.width - 8;
        if (top < 8) {
            top = rect.bottom + 8;
            tip.classList.add('pg-tooltip-below');
        }

        tip.style.left = left + window.scrollX + 'px';
        tip.style.top = top + window.scrollY + 'px';
        tip.classList.add('pg-tooltip-visible');

        return tip;
    }

    function removeTooltip() {
        if (activeTooltip) {
            activeTooltip.remove();
            activeTooltip = null;
        }
    }

    function init() {
        document.addEventListener('mouseenter', function (e) {
            var el = e.target.closest('[data-tip]');
            if (!el) return;
            removeTooltip();
            activeTooltip = createTooltip(el);
        }, true);

        document.addEventListener('mouseleave', function (e) {
            var el = e.target.closest('[data-tip]');
            if (!el) return;
            removeTooltip();
        }, true);

        document.addEventListener('focusin', function (e) {
            var el = e.target.closest('[data-tip]');
            if (!el) return;
            removeTooltip();
            activeTooltip = createTooltip(el);
        }, true);

        document.addEventListener('focusout', function (e) {
            var el = e.target.closest('[data-tip]');
            if (!el) return;
            removeTooltip();
        }, true);
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

    /* ============================================================
     * GUIDED WALKTHROUGH (activated by ?guided=1 URL parameter)
     * ============================================================ */
    var WALKTHROUGH_STEPS = [
        {
            selector: '.verdict-card',
            title: 'Threat Verdict',
            text: 'This is the overall threat assessment. The score ring shows the risk level from 0 (safe) to 100 (critical). The color indicates severity: green is clean, yellow is suspicious, red is dangerous.',
        },
        {
            selector: '[data-section="auth"]',
            title: 'Email Authentication',
            text: 'These badges show whether the email passed SPF, DKIM, and DMARC checks. Green "PASS" means the sender is verified. Red "FAIL" means the email may be spoofed \u2014 someone pretending to be someone else.',
        },
        {
            selector: '[data-section="urls"]',
            title: 'URL Analysis',
            text: 'Every link in the email is inspected. We check for look-alike domains, follow redirects, and even render pages in a sandbox to detect credential-stealing forms. Red indicators mean danger.',
        },
        {
            selector: '[data-section="attachments"]',
            title: 'Attachment Scanning',
            text: 'Attachments are scanned for malware signatures, checked against virus databases, and analyzed for hidden macros or executable code disguised as documents.',
        },
        {
            selector: '[data-section="breakdown"]',
            title: 'Score Breakdown',
            text: 'This table shows every individual finding that contributed to the threat score. Each row shows what was detected, which category it falls under, and how many risk points it added.',
        },
        {
            selector: '[data-section="iocs"]',
            title: 'Indicators of Compromise',
            text: 'IOCs are the specific artifacts \u2014 IP addresses, domains, URLs, and file hashes \u2014 extracted from the email. Security teams use these to block threats across their network.',
        },
    ];

    function startWalkthrough() {
        var params = new URLSearchParams(window.location.search);
        if (params.get('guided') !== '1') return;

        var currentStep = 0;
        var overlay = document.createElement('div');
        overlay.className = 'walkthrough-overlay';
        document.body.appendChild(overlay);

        var card = document.createElement('div');
        card.className = 'walkthrough-card';
        document.body.appendChild(card);

        function showStep(idx) {
            if (idx < 0 || idx >= WALKTHROUGH_STEPS.length) {
                overlay.remove();
                card.remove();
                // Remove guided param from URL
                params.delete('guided');
                var newUrl = window.location.pathname;
                if (params.toString()) newUrl += '?' + params.toString();
                window.history.replaceState({}, '', newUrl);
                return;
            }
            currentStep = idx;
            var step = WALKTHROUGH_STEPS[idx];
            var target = document.querySelector(step.selector);

            // Clear previous highlights
            document.querySelectorAll('.walkthrough-highlight').forEach(function (el) {
                el.classList.remove('walkthrough-highlight');
            });

            if (target) {
                target.classList.add('walkthrough-highlight');
                target.scrollIntoView({ behavior: 'smooth', block: 'center' });
            }

            card.innerHTML =
                '<div class="wt-step-count">Step ' + (idx + 1) + ' of ' + WALKTHROUGH_STEPS.length + '</div>' +
                '<h3 class="wt-title">' + step.title + '</h3>' +
                '<p class="wt-text">' + step.text + '</p>' +
                '<div class="wt-buttons">' +
                (idx > 0 ? '<button class="wt-btn wt-btn-back" onclick="this._wtPrev()">Back</button>' : '<span></span>') +
                (idx < WALKTHROUGH_STEPS.length - 1
                    ? '<button class="wt-btn wt-btn-next">Next</button>'
                    : '<button class="wt-btn wt-btn-finish">Finish</button>') +
                '</div>';

            var backBtn = card.querySelector('.wt-btn-back');
            if (backBtn) backBtn.addEventListener('click', function () { showStep(idx - 1); });
            var nextBtn = card.querySelector('.wt-btn-next');
            if (nextBtn) nextBtn.addEventListener('click', function () { showStep(idx + 1); });
            var finishBtn = card.querySelector('.wt-btn-finish');
            if (finishBtn) finishBtn.addEventListener('click', function () { showStep(WALKTHROUGH_STEPS.length); });
        }

        // Start after a brief delay for page to render
        setTimeout(function () { showStep(0); }, 500);
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', startWalkthrough);
    } else {
        startWalkthrough();
    }
})();
