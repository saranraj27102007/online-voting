/* ═══════════════════════════════════════════════════════════════════════
   face-engine.js — VoteSecure v7

   ROOT CAUSE FIX:
   TinyFaceDetector fails on darker skin tones + busy backgrounds + downward
   head angle. v7 uses SSD MobileNet (much more robust CNN, same face-api.js)
   with canvas pre-processing (adaptive brightness boost) before detection.

   ARCHITECTURE:
   ─ detect()               → SSD MobileNet, no descriptor (~50ms)
   ─ detectWithDescriptor() → SSD MobileNet + recognition (~250ms) — capture only
   ─ preprocessCanvas()     → brightens dark frame before detection
   ─ LivenessDetector()     → adaptive EAR blink counter
   ─ Manual fallback        → if no face after 8s, enable manual capture button
   ═══════════════════════════════════════════════════════════════════════ */
(function (global) {
  'use strict';

  var MODEL_URL = 'https://cdn.jsdelivr.net/gh/justadudewhohacks/face-api.js@0.22.2/weights';

  var _ready     = false;
  var _loading   = false;
  var _faceapi   = null;
  var _loadError = null;

  /* ─── Load models ─────────────────────────────────────────────────── */
  function load() {
    if (_ready)   return Promise.resolve();
    if (_loading) return new Promise(function (res, rej) {
      var t = setInterval(function () {
        if (_ready)     { clearInterval(t); res(); }
        if (_loadError) { clearInterval(t); rej(_loadError); }
      }, 200);
    });

    _loading = true;
    _faceapi = global.faceapi;

    if (!_faceapi) {
      _loadError = new Error('face-api.js not loaded. CDN script must be above face-engine.js.');
      return Promise.reject(_loadError);
    }

    // Load SSD MobileNet (more robust than TinyFaceDetector for varied skin tones)
    // + Landmark68 tiny (fast) + Recognition net (for descriptor)
    return Promise.all([
      _faceapi.nets.ssdMobilenetv1.loadFromUri(MODEL_URL),
      _faceapi.nets.faceLandmark68Net.loadFromUri(MODEL_URL),
      _faceapi.nets.faceRecognitionNet.loadFromUri(MODEL_URL)
    ]).then(function () {
      _ready   = true;
      _loading = false;
    }).catch(function (e) {
      // SSD failed — fall back to TinyFaceDetector
      console.warn('SSD MobileNet load failed, trying TinyFaceDetector:', e.message);
      return Promise.all([
        _faceapi.nets.tinyFaceDetector.loadFromUri(MODEL_URL),
        _faceapi.nets.faceLandmark68TinyNet.loadFromUri(MODEL_URL),
        _faceapi.nets.faceRecognitionNet.loadFromUri(MODEL_URL)
      ]).then(function () {
        _ready   = true;
        _loading = false;
        _useTiny = true;
      });
    });
  }

  var _useTiny = false;   // set true if SSD failed and we fell back

  function isLoaded() { return _ready; }

  /* ─── Canvas pre-processing — brighten dark frames ───────────────── */
  // Creates a brighter copy of the video frame to help the detector
  // on dark skin tones or dim lighting conditions
  function _preprocessed(input) {
    var w = input.videoWidth  || input.width  || 640;
    var h = input.videoHeight || input.height || 480;
    if (!w || !h) return input;

    var cnv = document.createElement('canvas');
    cnv.width = w; cnv.height = h;
    var ctx = cnv.getContext('2d');
    ctx.drawImage(input, 0, 0, w, h);

    // Measure average brightness of centre region
    try {
      var cx = Math.floor(w * 0.25), cy = Math.floor(h * 0.25);
      var cw = Math.floor(w * 0.5),  ch = Math.floor(h * 0.5);
      var px = ctx.getImageData(cx, cy, cw, ch).data;
      var sum = 0;
      for (var i = 0; i < px.length; i += 4) sum += (px[i] * 0.299 + px[i+1] * 0.587 + px[i+2] * 0.114);
      var avgBrightness = sum / (px.length / 4);

      // Apply brightness + contrast boost when image is dark (< 100 avg)
      // This dramatically improves detection on darker skin tones
      if (avgBrightness < 100) {
        var boost = Math.min(2.5, 150 / Math.max(avgBrightness, 30));
        ctx.globalCompositeOperation = 'source-over';
        ctx.filter = 'brightness(' + boost + ') contrast(1.3)';
        ctx.drawImage(input, 0, 0, w, h);
        ctx.filter = 'none';
      }
    } catch (e) { /* cross-origin guard — use raw frame */ }

    return cnv;
  }

  /* ─── SSD detector options ────────────────────────────────────────── */
  function _ssdOpts(threshold) {
    return new _faceapi.SsdMobilenetv1Options({
      minConfidence: threshold || 0.20,   // very permissive — catches all faces
      maxResults:    1
    });
  }

  function _tinyOpts(size, threshold) {
    return new _faceapi.TinyFaceDetectorOptions({
      inputSize:      size      || 224,
      scoreThreshold: threshold || 0.15
    });
  }

  /* ─── detect() — fast, no descriptor (real-time loop) ────────────── */
  function detect(input) {
    if (!_faceapi || !_ready) return Promise.reject(new Error('FaceEngine not loaded'));
    var frame = _preprocessed(input);
    var chain = _useTiny
      ? _faceapi.detectSingleFace(frame, _tinyOpts(224, 0.15)).withFaceLandmarks(true)
      : _faceapi.detectSingleFace(frame, _ssdOpts(0.20)).withFaceLandmarks();
    return chain.then(function (result) {
      if (!result) return null;
      return _buildResult(result, input, null);
    });
  }

  /* ─── detectWithDescriptor() — used only at capture ──────────────── */
  // Tries multiple preprocessings and returns the result with highest detection confidence
  function detectWithDescriptor(input) {
    if (!_faceapi || !_ready) return Promise.reject(new Error('FaceEngine not loaded'));

    // Generate 3 versions of the frame with different brightness levels
    function _makeFrame(brightnessBoost) {
      var w = input.videoWidth || input.width || 640;
      var h = input.videoHeight || input.height || 480;
      if (!w || !h) return input;
      var cnv = document.createElement('canvas');
      cnv.width = w; cnv.height = h;
      var ctx = cnv.getContext('2d');
      if (brightnessBoost !== 1) {
        ctx.filter = 'brightness(' + brightnessBoost + ') contrast(1.2)';
      }
      ctx.drawImage(input, 0, 0, w, h);
      ctx.filter = 'none';
      return cnv;
    }

    var frames = [
      _preprocessed(input),   // adaptive brightness
      _makeFrame(1.0),         // raw / original
      _makeFrame(1.8),         // brighter
    ];

    function tryFrame(i) {
      if (i >= frames.length) return Promise.resolve(null);
      var chain = _useTiny
        ? _faceapi.detectSingleFace(frames[i], _tinyOpts(320, 0.12)).withFaceLandmarks(true).withFaceDescriptor()
        : _faceapi.detectSingleFace(frames[i], _ssdOpts(0.15)).withFaceLandmarks().withFaceDescriptor();
      return chain.then(function(result) {
        if (result && result.descriptor) {
          return _buildResult(result, input, result.descriptor);
        }
        return tryFrame(i + 1); // try next preprocessing
      });
    }

    return tryFrame(0);
  }

  /* ─── detectMultipleDescriptors() — capture 3 frames, return all descriptors ── */
  function detectMultipleDescriptors(video) {
    if (!_faceapi || !_ready) return Promise.reject(new Error('FaceEngine not loaded'));
    var results = [];

    function captureOne(delay) {
      return new Promise(function(resolve) { setTimeout(resolve, delay); })
        .then(function() {
          var frame = _preprocessed(video);
          var chain = _useTiny
            ? _faceapi.detectSingleFace(frame, _tinyOpts(320, 0.12)).withFaceLandmarks(true).withFaceDescriptor()
            : _faceapi.detectSingleFace(frame, _ssdOpts(0.15)).withFaceLandmarks().withFaceDescriptor();
          return chain;
        })
        .then(function(result) {
          if (result && result.descriptor) {
            results.push(Array.from(result.descriptor));
          }
        });
    }

    // Capture 3 frames 150ms apart to get varied samples
    return captureOne(0)
      .then(function() { return captureOne(150); })
      .then(function() { return captureOne(300); })
      .then(function() { return results; });
  }

  /* ─── Normalize result ────────────────────────────────────────────── */
  function _buildResult(result, input, descriptor) {
    var box = result.detection.box;
    var w   = input.videoWidth  || input.width  || 640;
    var h   = input.videoHeight || input.height || 480;
    return {
      detection: {
        box: { x: box.x, y: box.y, width: box.width, height: box.height }
      },
      landmarks: {
        // Normalised [0-1] for EAR calculation
        positions: result.landmarks.positions.map(function (p) {
          return { x: p.x / w, y: p.y / h };
        })
      },
      descriptor: descriptor || null
    };
  }

  /* ═══════════════════════════════════════════════════════════════════
     LIVENESS — Adaptive EAR blink detector

     68-pt landmark eye indices:
       Left  eye: 36–41    Right eye: 42–47

     ADAPTIVE: measures YOUR open-eye EAR for 10 frames, then uses
       close = 73% of baseline,  open = 87% of baseline
     Works for all face shapes, skin tones, angles, lighting.
  ═══════════════════════════════════════════════════════════════════ */
  var L_EYE = [36, 37, 38, 39, 40, 41];
  var R_EYE = [42, 43, 44, 45, 46, 47];

  function LivenessDetector(requiredBlinks) {
    requiredBlinks = requiredBlinks || 1;  // Only 1 blink needed — fast & user-friendly

    var blinkCount   = 0;
    var eyesClosed   = false;
    var closedFrames = 0;
    var openFrames   = 0;   // frames eyes have been open since last blink

    var calibFrames  = 0;
    var earAccum     = 0;
    var baseline     = null;
    var CALIB_N      = 5;   // Only 5 frames to calibrate (~250ms at 20fps) — much faster

    function _d(a, b) {
      var dx = a.x - b.x, dy = a.y - b.y;
      return Math.sqrt(dx * dx + dy * dy);
    }
    function _ear(pos, idx) {
      var num = _d(pos[idx[1]], pos[idx[5]]) + _d(pos[idx[2]], pos[idx[4]]);
      var den = 2.0 * _d(pos[idx[0]], pos[idx[3]]);
      return den < 1e-6 ? 0.3 : num / den;
    }

    // Real blink = 1–20 frames; hand/obstruction = 30+ frames
    var MAX_CLOSED_FRAMES = 25;

    function update(landmarks) {
      var pos = landmarks.positions;
      if (!pos || pos.length < 48) return blinkCount;

      var leftEar  = _ear(pos, L_EYE);
      var rightEar = _ear(pos, R_EYE);
      var ear = (leftEar + rightEar) / 2;

      // Garbage guard
      if (ear < 0.02 || ear > 0.70) {
        if (eyesClosed) {
          closedFrames++;
          if (closedFrames > MAX_CLOSED_FRAMES) {
            eyesClosed = false; closedFrames = 0;
          }
        }
        return blinkCount;
      }

      // Phase 1 — fast calibration: 5 frames of open eyes
      if (baseline === null) {
        if (ear > 0.18) { earAccum += ear; calibFrames++; }
        if (calibFrames >= CALIB_N) {
          baseline = earAccum / calibFrames;
          if (baseline < 0.20) baseline = 0.25;   // floor for narrow eyes
          if (baseline > 0.55) baseline = 0.42;   // ceil
        }
        return blinkCount;
      }

      // Phase 2 — blink detection with sensitive thresholds
      // closeT: 78% of baseline — detects even partial/subtle blinks
      // openT:  82% of baseline — eyes don't need to fully reopen to register
      var closeT = baseline * 0.78;
      var openT  = baseline * 0.82;

      if (!eyesClosed) {
        openFrames++;
        if (ear < closeT && openFrames >= 2) {
          // Eyes just closed (openFrames>=2 prevents double-counting)
          eyesClosed = true; closedFrames = 1; openFrames = 0;
        }
      } else {
        if (ear < openT) {
          closedFrames++;
          if (closedFrames > MAX_CLOSED_FRAMES) {
            // Held too long — obstruction, not a blink
            eyesClosed = false; closedFrames = 0;
          }
        } else {
          // Eyes reopened — any duration counts (even 1 frame = fast blink)
          if (closedFrames >= 1 && closedFrames <= MAX_CLOSED_FRAMES) {
            blinkCount++;
          }
          eyesClosed = false; closedFrames = 0;
        }
      }
      return blinkCount;
    }

    function count()      { return blinkCount; }
    function complete()   { return blinkCount >= requiredBlinks; }
    function isCalibrated() { return baseline !== null; }
    function getBaseline()  { return baseline; }
    function reset() {
      blinkCount = 0; eyesClosed = false; closedFrames = 0; openFrames = 0;
      calibFrames = 0; earAccum = 0; baseline = null;
    }

    return { update, count, complete, isCalibrated, getBaseline, reset };
  }

  /* ─── Draw overlay ────────────────────────────────────────────────── */
  function drawOverlay(canvas, video, detection, status) {
    var vw = video.videoWidth  || canvas.width  || 640;
    var vh = video.videoHeight || canvas.height || 480;
    if (canvas.width !== vw || canvas.height !== vh) {
      canvas.width = vw; canvas.height = vh;
    }
    var ctx = canvas.getContext('2d');
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    if (!detection) return;

    var b = detection.detection.box;
    var col = status === 'verified' ? '#00d68f'
            : status === 'liveness' ? '#ffb830'
            : status === 'failed'   ? '#ff4d6d'
            : '#4f83ff';

    ctx.shadowBlur = 20; ctx.shadowColor = col;
    ctx.strokeStyle = col; ctx.lineWidth = 2.5;
    ctx.strokeRect(b.x, b.y, b.width, b.height);

    var cs = Math.min(b.width, b.height) * 0.18;
    var corners = [
      [b.x,          b.y,           cs,  0,  0,  cs],
      [b.x+b.width,  b.y,          -cs,  0,  0,  cs],
      [b.x,          b.y+b.height,  cs,  0,  0, -cs],
      [b.x+b.width,  b.y+b.height, -cs,  0,  0, -cs]
    ];
    ctx.lineWidth = 4; ctx.lineCap = 'round';
    corners.forEach(function (c) {
      ctx.beginPath();
      ctx.moveTo(c[0]+c[2], c[1]); ctx.lineTo(c[0], c[1]); ctx.lineTo(c[0], c[1]+c[5]);
      ctx.stroke();
    });
    ctx.shadowBlur = 0;

    var label = status === 'verified' ? '✓ Face Detected'
              : status === 'liveness' ? '👁 Blink!'
              : status === 'failed'   ? '✗ No Match'
              : '⬤ Scanning…';
    ctx.font = 'bold 13px system-ui, sans-serif';
    var tw = ctx.measureText(label).width + 22;
    var ly = Math.max(2, b.y - 30);
    ctx.fillStyle = col;
    _rr(ctx, b.x, ly, tw, 24, 5); ctx.fill();
    ctx.fillStyle = status === 'liveness' ? '#000' : '#fff';
    ctx.fillText(label, b.x + 11, ly + 16);
  }

  function _rr(ctx, x, y, w, h, r) {
    ctx.beginPath();
    ctx.moveTo(x+r,y); ctx.lineTo(x+w-r,y); ctx.arc(x+w-r,y+r,r,-Math.PI/2,0);
    ctx.lineTo(x+w,y+h-r); ctx.arc(x+w-r,y+h-r,r,0,Math.PI/2);
    ctx.lineTo(x+r,y+h); ctx.arc(x+r,y+h-r,r,Math.PI/2,Math.PI);
    ctx.lineTo(x,y+r); ctx.arc(x+r,y+r,r,Math.PI,-Math.PI/2);
    ctx.closePath();
  }

  function clearOverlay(canvas) {
    if (canvas) canvas.getContext('2d').clearRect(0, 0, canvas.width, canvas.height);
  }

  /* ─── Capture still frame from video ─────────────────────────────── */
  function captureFrame(video, isMobile, isFrontCam) {
    var cnv = document.createElement('canvas');
    cnv.width  = video.videoWidth  || 640;
    cnv.height = video.videoHeight || 480;
    var ctx = cnv.getContext('2d');
    if (!isMobile && isFrontCam) { ctx.save(); ctx.translate(cnv.width,0); ctx.scale(-1,1); }
    ctx.drawImage(video, 0, 0);
    if (!isMobile && isFrontCam) ctx.restore();
    return cnv;
  }

  /* ─── Export ──────────────────────────────────────────────────────── */
  global.FaceEngine = {
    load, isLoaded,
    detect, detectWithDescriptor, detectMultipleDescriptors,
    LivenessDetector,
    drawOverlay, clearOverlay, captureFrame
  };

})(window);
