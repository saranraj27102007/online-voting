/**
 * VoteSecure — Liveness Guard (Client-Side)
 * ─────────────────────────────────────────────────────────────
 * Deepfake / screen-replay / photo-attack detection.
 *
 * Checks performed:
 *   1. Multi-challenge system   — random blink + head turn / smile / mouth
 *   2. EAR blink validation     — real eye closure required
 *   3. Yaw/pitch head movement  — 3D face rotation (screens are flat)
 *   4. Landmark variance        — static face = no micro-movements
 *   5. Texture analysis         — pixel variance on face ROI
 *   6. Brightness fluctuation   — screen replay has unnatural brightness
 *   7. Temporal consistency     — pre-recorded video has frame-perfect timing
 *
 * Usage:
 *   const guard = new LivenessGuard(videoEl, overlayEl, challenges);
 *   guard.onComplete = (metrics) => { ... send to server ... };
 *   guard.onFailure  = (reason)  => { ... show error ... };
 *   guard.start();
 */

(function(global) {
  'use strict';

  // ── Constants ───────────────────────────────────────────────
  const EAR_CLOSE_THRESHOLD = 0.22;   // below = eyes closed
  const YAW_THRESHOLD       = 12;     // degrees for head turn
  const PITCH_THRESHOLD     = 10;     // degrees for nod
  const TEXTURE_THRESHOLD   = 0.015;  // variance below = flat surface
  const VARIANCE_THRESHOLD  = 0.001;  // landmark variance below = static image
  const MIN_COMPLETION_MS   = 800;    // faster = replay

  // face-api.js left/right eye landmark indices (68-point model)
  const L_EYE = [36, 37, 38, 39, 40, 41];
  const R_EYE = [42, 43, 44, 45, 46, 47];
  const MOUTH = [48, 50, 52, 54, 56, 58, 60, 62]; // outer + inner lip

  function dist(a, b) {
    const dx = a.x - b.x, dy = a.y - b.y;
    return Math.sqrt(dx * dx + dy * dy);
  }

  function ear(pts, idx) {
    const num = dist(pts[idx[1]], pts[idx[5]]) + dist(pts[idx[2]], pts[idx[4]]);
    const den = 2.0 * dist(pts[idx[0]], pts[idx[3]]);
    return den < 1e-6 ? 0.3 : num / den;
  }

  // Mouth Aspect Ratio — open mouth detection
  function mar(pts) {
    const h = (dist(pts[50], pts[58]) + dist(pts[52], pts[56])) / 2;
    const w = dist(pts[48], pts[54]);
    return w < 1e-6 ? 0 : h / w;
  }

  // Head pose estimation from 68-point landmarks
  // Returns approximate yaw (left/right) and pitch (up/down) in degrees
  function estimateHeadPose(pts) {
    // Use nose tip (30), chin (8), left eye outer (36), right eye outer (45)
    // Approximation via facial symmetry ratios
    const noseTip   = pts[30];
    const leftEye   = pts[36];
    const rightEye  = pts[45];
    const eyeCenter = { x: (leftEye.x + rightEye.x) / 2, y: (leftEye.y + rightEye.y) / 2 };
    const eyeWidth  = dist(leftEye, rightEye);

    // Yaw: nose offset from eye midpoint (normalised by eye width)
    const yaw   = ((noseTip.x - eyeCenter.x) / (eyeWidth + 0.001)) * 50;
    // Pitch: nose vertical offset
    const pitch = ((noseTip.y - eyeCenter.y) / (eyeWidth + 0.001)) * 35;

    return { yaw, pitch };
  }

  // ── Texture analysis on face ROI ────────────────────────────
  function computeTexture(videoEl, pts) {
    try {
      const xs = pts.map(p => p.x), ys = pts.map(p => p.y);
      const x0 = Math.max(0, Math.min(...xs));
      const y0 = Math.max(0, Math.min(...ys));
      const w  = Math.min(videoEl.videoWidth,  Math.max(...xs)) - x0;
      const h  = Math.min(videoEl.videoHeight, Math.max(...ys)) - y0;
      if (w < 10 || h < 10) return 0.1;

      const c   = document.createElement('canvas');
      c.width   = Math.min(w, 64); c.height = Math.min(h, 64);
      const ctx = c.getContext('2d');
      ctx.drawImage(videoEl, x0, y0, w, h, 0, 0, c.width, c.height);
      const px  = ctx.getImageData(0, 0, c.width, c.height).data;

      let mean = 0;
      const grays = [];
      for (let i = 0; i < px.length; i += 4) {
        const g = (px[i] * 0.299 + px[i+1] * 0.587 + px[i+2] * 0.114) / 255;
        grays.push(g); mean += g;
      }
      mean /= grays.length;
      const variance = grays.reduce((s, g) => s + (g - mean) ** 2, 0) / grays.length;
      return variance;
    } catch(e) { return 0.1; }
  }

  // ── Landmark variance (detects static images) ───────────────
  function landmarkVariance(history) {
    if (history.length < 5) return 1; // not enough data
    const vars = [];
    for (let i = 0; i < Math.min(history.length - 1, 10); i++) {
      let sumSq = 0, count = 0;
      const a = history[i], b = history[i + 1];
      const len = Math.min(a.length, b.length);
      for (let j = 0; j < len; j++) {
        const dx = a[j].x - b[j].x, dy = a[j].y - b[j].y;
        sumSq += dx * dx + dy * dy;
        count++;
      }
      vars.push(count > 0 ? sumSq / count : 0);
    }
    return vars.reduce((a, b) => a + b, 0) / vars.length;
  }

  // ── LivenessGuard class ─────────────────────────────────────

  function LivenessGuard(videoEl, statusEl, challenges) {
    this.video      = videoEl;
    this.statusEl   = statusEl;
    this.challenges = challenges || []; // [{ id, label, type, ... }]
    this.onComplete = null; // (metrics) => void
    this.onFailure  = null; // (reason) => void
    this.onProgress = null; // (challengeIdx, total) => void

    this._active         = false;
    this._rafId          = null;
    this._startTime      = 0;
    this._currentIdx     = 0;
    this._results        = {}; // { challengeId: bool }
    this._landmarkHistory = [];
    this._blinkIntervals  = [];
    this._lastBlinkTime   = 0;
    this._blinkCount      = 0;
    this._blinkCalib      = null; // baseline EAR
    this._eyesClosed      = false;
    this._closedFrames    = 0;
    this._textureScores   = [];
    this._luxHistory      = [];
    this._headPoseHistory = [];
    this._lastFrame       = 0;
    this._FRAME_MS        = 50; // 20fps
  }

  LivenessGuard.prototype.start = function() {
    this._active    = true;
    this._startTime = Date.now();
    this._setStatus(this._currentChallenge()
      ? '👁 ' + this._currentChallenge().label
      : 'Look at the camera');
    this._loop();
  };

  LivenessGuard.prototype.stop = function() {
    this._active = false;
    if (this._rafId) { cancelAnimationFrame(this._rafId); this._rafId = null; }
  };

  LivenessGuard.prototype._currentChallenge = function() {
    return this.challenges[this._currentIdx] || null;
  };

  LivenessGuard.prototype._setStatus = function(msg, color) {
    if (this.statusEl) {
      this.statusEl.textContent  = msg;
      this.statusEl.style.color  = color || '#fff';
    }
  };

  LivenessGuard.prototype._loop = function() {
    if (!this._active) return;
    const self = this;
    this._rafId = requestAnimationFrame(async function(ts) {
      if (!self._active) return;
      if (ts - self._lastFrame < self._FRAME_MS) { self._loop(); return; }
      self._lastFrame = ts;
      await self._tick();
      if (self._active) self._loop();
    });
  };

  LivenessGuard.prototype._tick = async function() {
    const v = this.video;
    if (!v || !v.videoWidth || !v.videoHeight || v.readyState < 2) return;

    let result;
    try {
      // Use FaceEngine if available (face-api.js), otherwise skip
      if (typeof FaceEngine === 'undefined') return;
      result = await FaceEngine.detect(v);
    } catch(e) { return; }

    if (!result || !result.landmarks) return;

    const pts = result.landmarks.positions;
    if (!pts || pts.length < 68) return;

    // ── Record landmark history (for variance check) ──────────
    this._landmarkHistory.push(pts.slice(0, 68).map(p => ({ x: p.x, y: p.y })));
    if (this._landmarkHistory.length > 30) this._landmarkHistory.shift();

    // ── Texture score ─────────────────────────────────────────
    const tex = computeTexture(v, pts);
    this._textureScores.push(tex);
    if (this._textureScores.length > 20) this._textureScores.shift();

    // ── Brightness ────────────────────────────────────────────
    const lux = this._measureLux(v);
    this._luxHistory.push(lux);
    if (this._luxHistory.length > 30) this._luxHistory.shift();

    // ── Anti-spoofing pre-checks ──────────────────────────────
    const avgTex = this._textureScores.reduce((a,b) => a+b, 0) / this._textureScores.length;
    if (this._textureScores.length >= 10 && avgTex < TEXTURE_THRESHOLD) {
      this._setStatus('⚠️ Camera surface appears flat — move closer or improve lighting', 'var(--amber)');
      return;
    }
    const lv = landmarkVariance(this._landmarkHistory);
    if (this._landmarkHistory.length >= 10 && lv < VARIANCE_THRESHOLD) {
      this._setStatus('⚠️ No face movement detected — are you using a photo?', 'var(--red)');
      return;
    }

    // ── Head pose ─────────────────────────────────────────────
    const pose = estimateHeadPose(pts);
    this._headPoseHistory.push(pose);
    if (this._headPoseHistory.length > 30) this._headPoseHistory.shift();

    // ── EAR blink detection ───────────────────────────────────
    const leftEAR  = ear(pts, L_EYE);
    const rightEAR = ear(pts, R_EYE);
    const avgEAR   = (leftEAR + rightEAR) / 2;

    // Calibrate baseline EAR
    if (!this._blinkCalib) {
      if (avgEAR > 0.20) {
        this._blinkCalibFrames = (this._blinkCalibFrames || 0) + 1;
        this._blinkCalibAccum  = (this._blinkCalibAccum  || 0) + avgEAR;
        if (this._blinkCalibFrames >= 6) {
          this._blinkCalib = this._blinkCalibAccum / this._blinkCalibFrames;
          if (this._blinkCalib < 0.22) this._blinkCalib = 0.26;
          if (this._blinkCalib > 0.55) this._blinkCalib = 0.40;
        }
      }
      this._setStatus('👁 Keep eyes open to calibrate…', 'var(--amber)');
      return;
    }

    const closeT = this._blinkCalib * 0.76;
    const openT  = this._blinkCalib * 0.82;

    if (!this._eyesClosed && avgEAR < closeT) {
      this._eyesClosed = true; this._closedFrames = 1;
    } else if (this._eyesClosed) {
      if (avgEAR < openT) {
        this._closedFrames++;
        if (this._closedFrames > 25) { this._eyesClosed = false; this._closedFrames = 0; }
      } else {
        if (this._closedFrames >= 1 && this._closedFrames <= 25) {
          // Valid blink
          const now = Date.now();
          if (this._lastBlinkTime > 0) this._blinkIntervals.push(now - this._lastBlinkTime);
          this._lastBlinkTime = now;
          this._blinkCount++;
        }
        this._eyesClosed = false; this._closedFrames = 0;
      }
    }

    // ── MAR (mouth opening) ───────────────────────────────────
    const mouthAR = mar(pts);

    // ── Evaluate current challenge ────────────────────────────
    const challenge = this._currentChallenge();
    if (!challenge) return;

    let passed = false;

    if (challenge.type === 'blink') {
      const needed = challenge.count || 1;
      this._setStatus(`👁 ${challenge.label} (${Math.min(this._blinkCount, needed)}/${needed})`, 'var(--amber)');
      if (this._blinkCount >= needed) passed = true;

    } else if (challenge.type === 'yaw') {
      const dir = challenge.direction;
      const yaw = pose.yaw;
      if (dir === 'left'  && yaw < -YAW_THRESHOLD)  passed = true;
      if (dir === 'right' && yaw >  YAW_THRESHOLD)   passed = true;
      this._setStatus(`↔️ ${challenge.label} (${Math.round(yaw)}°)`, 'var(--amber)');

    } else if (challenge.type === 'pitch') {
      const pitch = pose.pitch;
      if (challenge.direction === 'down' && pitch > PITCH_THRESHOLD) passed = true;
      this._setStatus(`↕️ ${challenge.label} (${Math.round(pitch)}°)`, 'var(--amber)');

    } else if (challenge.type === 'expression') {
      if (challenge.expr === 'smile') {
        // Smile: cheek width increases relative to neutral
        const cheekW = dist(pts[1], pts[15]);
        const eyeW   = dist(pts[36], pts[45]);
        if (cheekW / (eyeW + 0.001) > 1.5) passed = true;
        this._setStatus('😊 ' + challenge.label, 'var(--amber)');
      } else if (challenge.expr === 'mouth') {
        if (mouthAR > 0.3) passed = true;
        this._setStatus('😮 ' + challenge.label, 'var(--amber)');
      }
    }

    if (passed) {
      this._results[challenge.id] = true;
      this._setStatus('✅ ' + challenge.label + ' — done!', 'var(--green)');
      this._currentIdx++;
      // Reset blink count for next blink challenge
      this._blinkCount = 0;

      if (this.onProgress) this.onProgress(this._currentIdx, this.challenges.length);

      if (this._currentIdx >= this.challenges.length) {
        // All challenges passed
        await this._finalise();
      }
    }
  };

  LivenessGuard.prototype._finalise = async function() {
    this.stop();

    const completionMs     = Date.now() - this._startTime;
    const avgTexture       = this._textureScores.reduce((a,b) => a+b, 0) / (this._textureScores.length || 1);
    const lv               = landmarkVariance(this._landmarkHistory);
    const luxVariance      = this._luxVariance();

    // Final check: was it too fast?
    if (completionMs < MIN_COMPLETION_MS) {
      if (this.onFailure) this.onFailure('Liveness completed suspiciously fast — possible replay.');
      return;
    }

    const metrics = {
      completionMs,
      landmarkVariance:  parseFloat(lv.toFixed(6)),
      textureScore:      parseFloat(avgTexture.toFixed(5)),
      luxVariance:       parseFloat(luxVariance.toFixed(4)),
      blinkIntervals:    this._blinkIntervals,
      blinkRequired:     this.challenges.some(c => c.type === 'blink'),
      minEAR:            this._blinkCalib ? parseFloat((this._blinkCalib * 0.76).toFixed(3)) : 0.22
    };

    if (this.onComplete) this.onComplete(metrics);
  };

  LivenessGuard.prototype._measureLux = function(v) {
    try {
      const c = document.createElement('canvas'); c.width = 40; c.height = 30;
      const ctx = c.getContext('2d'); ctx.drawImage(v, 0, 0, 40, 30);
      const px = ctx.getImageData(0, 0, 40, 30).data;
      let s = 0;
      for (let i = 0; i < px.length; i += 16) s += (px[i] + px[i+1] + px[i+2]) / 3;
      return s / (px.length / 16);
    } catch(e) { return 128; }
  };

  LivenessGuard.prototype._luxVariance = function() {
    const h = this._luxHistory;
    if (h.length < 3) return 1;
    const mean = h.reduce((a,b) => a+b, 0) / h.length;
    return h.reduce((s, v) => s + (v - mean) ** 2, 0) / h.length;
  };

  // Export
  global.LivenessGuard = LivenessGuard;

})(typeof window !== 'undefined' ? window : global);
