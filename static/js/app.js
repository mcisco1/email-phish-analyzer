document.addEventListener("DOMContentLoaded", function() {
    var dropZone = document.getElementById("drop-zone");
    var fileInput = document.getElementById("eml-input");
    var fileInfo = document.getElementById("file-info");
    var fileName = document.getElementById("file-name");
    var fileSize = document.getElementById("file-size");
    var submitBtn = document.getElementById("btn-submit");
    if (!dropZone || !fileInput) return;

    function handleFiles(files) {
        var validFiles = [];
        for (var i = 0; i < files.length; i++) {
            if (files[i].name.toLowerCase().endsWith(".eml")) {
                validFiles.push(files[i]);
            }
        }
        if (validFiles.length === 0) {
            alert("Please select .eml files");
            return;
        }
        if (validFiles.length === 1) {
            fileName.textContent = validFiles[0].name;
            fileSize.textContent = (validFiles[0].size / 1024).toFixed(1) + " KB";
        } else {
            fileName.textContent = validFiles.length + " files selected";
            var totalSize = 0;
            for (var j = 0; j < validFiles.length; j++) totalSize += validFiles[j].size;
            fileSize.textContent = (totalSize / 1024).toFixed(1) + " KB total";
        }
        fileInfo.style.display = "flex";
        submitBtn.disabled = false;
        submitBtn.textContent = validFiles.length > 1
            ? "Analyze " + validFiles.length + " Emails"
            : "Analyze Email";
    }

    fileInput.addEventListener("change", function() {
        if (this.files.length > 0) handleFiles(this.files);
    });

    dropZone.addEventListener("dragover", function(e) {
        e.preventDefault();
        this.classList.add("dragover");
    });

    dropZone.addEventListener("dragleave", function() {
        this.classList.remove("dragover");
    });

    dropZone.addEventListener("drop", function(e) {
        e.preventDefault();
        this.classList.remove("dragover");
        if (e.dataTransfer.files.length > 0) {
            fileInput.files = e.dataTransfer.files;
            handleFiles(e.dataTransfer.files);
        }
    });

    var form = document.getElementById("upload-form");
    if (form) {
        form.addEventListener("submit", function() {
            submitBtn.disabled = true;
            submitBtn.textContent = "Analyzing\u2026";
        });
    }
});
