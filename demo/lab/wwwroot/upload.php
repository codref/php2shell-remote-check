<?php
// php2shell remote-check lab — an upload route (no session_start()).
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    echo "received " . count($_FILES) . " file(s)\n";
} else {
    echo "upload form\n";
}
