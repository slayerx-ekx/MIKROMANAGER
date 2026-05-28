# Frontend Template Structure

This folder contains the modular Go-template version of the existing single-page UI.
The current Docker/Nginx runtime still serves `templates/index.html` unchanged for full backward compatibility.

- `../index.html` is the Go-template entrypoint. It defines `content` and renders `main`.
- `layouts/main.html` owns the document shell.
- `partials/head.html` keeps the original head assets and inline CSS unchanged.
- `partials/sidebar.html` keeps the original sidebar and mobile overlay unchanged.
- `partials/navbar.html` keeps the original top header unchanged.
- `partials/footer.html` keeps the original modal layer, toast layer, and inline JavaScript unchanged.
- `pages/*.html` keep the original page sections unchanged and are included by `content`.