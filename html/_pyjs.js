
    /* ── noVNC resize=remote 재전송: 1px 줄임→복원으로 resize 이벤트 유발 ── */
    (function() {
      var frame = document.getElementById('vnc-frame');
      function nudgeResize() {
        frame.style.right = '1px';
        setTimeout(function() { frame.style.right = '0px'; }, 200);
      }
      frame.addEventListener('load', function() {
        // 연결 후 1.5초 대기 → noVNC가 완전히 초기화된 뒤 resize 재전송
        setTimeout(nudgeResize, 1500);
      });

      /* ── B안: GPU 가속 + CSS 커버 마스크 + 500ms 디바운스 ── */
      var _resizeTimer = null;
      var _cover = document.getElementById('vnc-cover');
      window.addEventListener('resize', function() {
        // 커버 즉시 표시 (흰색 마스크로 전환 중 빈 화면 차단)
        if (_cover) { _cover.style.opacity = '1'; _cover.style.transition = 'opacity 0.05s ease-in'; }
        // 500ms 안정 후 nudge 전송 → 커버 페이드아웃
        clearTimeout(_resizeTimer);
        _resizeTimer = setTimeout(function() {
          nudgeResize();
          if (_cover) { _cover.style.transition = 'opacity 0.6s ease-out'; _cover.style.opacity = '0'; }
        }, 500);
      });

      // 흰색 커버 제거:
      // 조건 1 (서버): /screenshot 폴링 → X11에 Orange3 화면이 실제로 렌더됨 확인
      // 조건 2 (클라이언트): vnc-frame load 이후 최소 4초 경과 → noVNC가 VNC 데이터 수신·렌더 완료
      // 두 조건 모두 충족된 시점에 커버를 제거해 "미니맵은 보이는데 캔버스는 비어있는" 현상 방지
      (function() {
        var _sid = "test-sid";
        var _started = Date.now();
        var _maxWait = 60000;
        var _interval = 800;
        var RESIZE_SETTLE_MS = 1500;    // resize=remote 완료까지 최소 보장 대기
        var _iframeLoadTime = Date.now(); // 기본값: 페이지 로드 시각
        var frame = document.getElementById('vnc-frame');
        if (frame) {
          frame.addEventListener('load', function() {
            _iframeLoadTime = Date.now();
          });
        }
        function _removeCover() {
          var cover = document.getElementById('vnc-cover');
          if (cover) {
            cover.style.opacity = '0';
            setTimeout(function() { if (cover && cover.parentNode) cover.parentNode.removeChild(cover); }, 600);
          }
          /* Orange3 준비 완료 → noVNC iframe 자동 포커스 (키보드 이벤트 즉시 활성화) */
          var frame = document.getElementById('vnc-frame');
          if (frame) frame.focus();
        }
        /* 스크린샷 좌측상단(위젯 독 영역) 픽셀 평균 밝기 확인
           - 스플래시+검은 배경: 밝기 < 80  → 아직 로딩 중
           - 메인 캔버스(흰/회색): 밝기 ≥ 80 → 커버 제거 가능 */
        function _checkBright(blob) {
          return new Promise(function(resolve) {
            var url = URL.createObjectURL(blob);
            var img = new Image();
            img.onload = function() {
              try {
                var c = document.createElement('canvas');
                c.width = 80; c.height = 80;
                var ctx = c.getContext('2d');
                ctx.drawImage(img, 0, 0, 80, 80);
                var d = ctx.getImageData(0, 0, 80, 80).data;
                var sum = 0;
                for (var i = 0; i < d.length; i += 4) sum += (d[i] + d[i+1] + d[i+2]) / 3;
                resolve((sum / (d.length / 4)) > 80);
              } catch(e) { resolve(true); }
              URL.revokeObjectURL(url);
            };
            img.onerror = function() { URL.revokeObjectURL(url); resolve(false); };
            img.src = url;
          });
        }
        function _pollScreenshot() {
          if (!document.getElementById('vnc-cover')) return;
          fetch('/screenshot?sid=' + _sid + '&t=' + Date.now())
            .then(function(r) {
              if (r.ok && r.headers.get('content-type') && r.headers.get('content-type').startsWith('image/')) {
                r.blob().then(function(blob) {
                  _checkBright(blob).then(function(bright) {
                    if (bright) {
                      // 메인 캔버스 확인 + iframe load 후 RESIZE_SETTLE_MS 보장 (resize=remote 안정화)
                      var elapsed = Date.now() - _iframeLoadTime;
                      var wait = Math.max(RESIZE_SETTLE_MS, RESIZE_SETTLE_MS - elapsed);
                      setTimeout(_removeCover, wait);
                    } else {
                      // 아직 어두움(스플래시/검은 배경) → 0.5초 후 재폴링
                      if (Date.now() - _started < _maxWait) setTimeout(_pollScreenshot, 500);
                      else _removeCover();
                    }
                  });
                });
              } else {
                if (Date.now() - _started < _maxWait) setTimeout(_pollScreenshot, _interval);
                else _removeCover();
              }
            })
            .catch(function() {
              if (Date.now() - _started < _maxWait) setTimeout(_pollScreenshot, _interval);
              else _removeCover();
            });
        }
        setTimeout(_pollScreenshot, 500);
      })();
    })();

    let SID = "test-sid";

    /* ── 이 탭의 sessionStorage에 SID 저장 (탭별 세션 분리) ── */
    try { sessionStorage.setItem('orange3_sid', SID); } catch(_) {}

    /* ── 세션 keepalive: 2분마다 /ping 호출로 last_seen 갱신 (30분 타임아웃 방지) ── */
    (function() {
      function ping() { fetch('/ping?sid=' + SID).catch(function(){}); }
      ping();  // 페이지 로드 즉시 1회
      setInterval(ping, 120000);  // 이후 2분마다
    })();

    /* ── 파일 업로드 폴링 ── */
    const POLL_INTERVAL = 4000;
    let lastTriggered = 0;
    const TRIGGER_COOLDOWN = 5000;

    async function pollUploadRequest() {
      try {
        const r = await fetch('/upload-poll?sid=' + SID);
        const d = await r.json();
        if (d.requested && (Date.now() - lastTriggered) > TRIGGER_COOLDOWN) {
          lastTriggered = Date.now();
          document.getElementById('pc-file-input').click();
        }
      } catch (_) {}
    }

    document.getElementById('pc-file-input').addEventListener('change', async function() {
      const fileArray = Array.from(this.files);
      this.value = '';
      if (!fileArray.length) return;
      showToast(`${fileArray.length}개 파일 업로드 중...`);
      const uploaded = [], errors = [];
      for (const file of fileArray) {
        const fd = new FormData();
        fd.append('file', file);
        try {
          const r = await fetch('/upload?sid=' + SID, { method:'POST', body:fd });
          const d = await r.json();
          if (d.filename) uploaded.push(d.filename);
          else errors.push(`${file.name}: ${d.error || '서버 오류'}`);
        } catch (e) {
          errors.push(`${file.name}: 네트워크 오류`);
        }
      }
      if (uploaded.length) showToast(`✓ 업로드 완료: ${uploaded.join(', ')}`, 4000);
      if (errors.length)   showToast(`✗ 실패: ${errors.join(' | ')}`, 5000);
    });

    setInterval(pollUploadRequest, POLL_INTERVAL);

    /* ── Load Model 전용 업로드 폴링 (accept=".pkcls") ── */
    async function pollModelUploadRequest() {
      try {
        const r = await fetch('/upload-poll-model?sid=' + SID);
        const d = await r.json();
        if (d.requested && (Date.now() - lastTriggered) > TRIGGER_COOLDOWN) {
          lastTriggered = Date.now();
          document.getElementById('model-file-input').click();
        }
      } catch (_) {}
    }

    document.getElementById('model-file-input').addEventListener('change', async function() {
      const file = this.files[0];
      this.value = '';
      if (!file) return;
      showToast(`모델 업로드 중: ${file.name}`);
      const fd = new FormData();
      fd.append('file', file);
      try {
        const r = await fetch('/upload?sid=' + SID + '&kind=model', { method:'POST', body:fd });
        const d = await r.json();
        if (d.filename) showToast(`✓ 모델 업로드: ${d.filename}`, 4000);
        else            showToast(`✗ 실패: ${d.error || '서버 오류'}`, 5000);
      } catch (e) {
        showToast(`✗ 네트워크 오류`, 5000);
      }
    });

    setInterval(pollModelUploadRequest, POLL_INTERVAL);

    /* ── Import Images 전용 폴더 업로드 폴링 (webkitdirectory) ── */
    async function pollImageFolderUploadRequest() {
      try {
        const r = await fetch('/upload-poll-images?sid=' + SID);
        const d = await r.json();
        if (d.requested && (Date.now() - lastTriggered) > TRIGGER_COOLDOWN) {
          lastTriggered = Date.now();
          document.getElementById('image-folder-input').click();
        }
      } catch (_) {}
    }

    document.getElementById('image-folder-input').addEventListener('change', async function() {
      const fileArray = Array.from(this.files);
      this.value = '';
      if (!fileArray.length) return;
      // 이미지 확장자만 필터링
      const imgExts = ['.png','.jpg','.jpeg','.gif','.tiff','.tif','.bmp','.webp','.ico','.svg'];
      const imageFiles = fileArray.filter(function(f) {
        const lower = f.name.toLowerCase();
        return imgExts.some(function(ext) { return lower.endsWith(ext); });
      });
      if (!imageFiles.length) {
        showToast('이미지 파일이 없습니다', 3000);
        return;
      }
      showToast(`${imageFiles.length}개 이미지 업로드 중...`, 5000);
      // multipart 한 번에 모든 파일 + 각 파일의 webkitRelativePath 전송
      const fd = new FormData();
      for (const f of imageFiles) {
        // file 필드와 동일 인덱스의 relpath 필드 → 서버에서 페어링
        fd.append('files', f);
        fd.append('relpaths', f.webkitRelativePath || f.name);
      }
      try {
        const r = await fetch('/upload-images?sid=' + SID, { method:'POST', body:fd });
        const d = await r.json();
        if (d.ok) showToast(`✓ ${d.count}개 이미지 업로드 완료 → ${d.dir}`, 4000);
        else showToast(`✗ 업로드 실패: ${d.error || '서버 오류'}`, 5000);
      } catch (e) {
        showToast(`✗ 네트워크 오류`, 5000);
      }
    });

    setInterval(pollImageFolderUploadRequest, POLL_INTERVAL);

    /* ── Corpus 위젯 전용 코퍼스 파일 업로드 폴링 (.tab/.csv/.tsv/.txt) ── */
    async function pollCorpusUploadRequest() {
      try {
        const r = await fetch('/upload-poll-corpus?sid=' + SID);
        const d = await r.json();
        if (d.requested && (Date.now() - lastTriggered) > TRIGGER_COOLDOWN) {
          lastTriggered = Date.now();
          document.getElementById('corpus-file-input').click();
        }
      } catch (_) {}
    }

    document.getElementById('corpus-file-input').addEventListener('change', async function() {
      const file = this.files[0];
      this.value = '';
      if (!file) return;
      showToast(`코퍼스 업로드 중: ${file.name}`);
      const fd = new FormData();
      fd.append('file', file);
      try {
        const r = await fetch('/upload?sid=' + SID + '&kind=corpus', { method:'POST', body:fd });
        const d = await r.json();
        if (d.filename) showToast(`✓ 코퍼스 업로드: ${d.filename}`, 4000);
        else            showToast(`✗ 실패: ${d.error || '서버 오류'}`, 5000);
      } catch (e) {
        showToast(`✗ 네트워크 오류`, 5000);
      }
    });

    setInterval(pollCorpusUploadRequest, POLL_INTERVAL);

    /* ── Import Documents 전용 폴더 업로드 폴링 (webkitdirectory, 모든 파일) ── */
    async function pollDocumentsFolderUploadRequest() {
      try {
        const r = await fetch('/upload-poll-documents?sid=' + SID);
        const d = await r.json();
        if (d.requested && (Date.now() - lastTriggered) > TRIGGER_COOLDOWN) {
          lastTriggered = Date.now();
          document.getElementById('documents-folder-input').click();
        }
      } catch (_) {}
    }

    document.getElementById('documents-folder-input').addEventListener('change', async function() {
      const fileArray = Array.from(this.files);
      this.value = '';
      if (!fileArray.length) return;
      // Import Documents 는 .txt/.pdf/.docx/.conllu/.html 등 다양 — 텍스트성 확장자 우선
      const docExts = ['.txt','.pdf','.docx','.doc','.html','.htm','.xml','.json','.csv','.tsv','.conllu','.md','.rtf','.odt'];
      const docFiles = fileArray.filter(function(f) {
        const lower = f.name.toLowerCase();
        return docExts.some(function(ext) { return lower.endsWith(ext); });
      });
      if (!docFiles.length) {
        showToast('문서 파일이 없습니다 (.txt/.pdf/.docx 등)', 3000);
        return;
      }
      showToast(`${docFiles.length}개 문서 업로드 중...`, 5000);
      const fd = new FormData();
      for (const f of docFiles) {
        fd.append('files', f);
        fd.append('relpaths', f.webkitRelativePath || f.name);
      }
      try {
        const r = await fetch('/upload-documents?sid=' + SID, { method:'POST', body:fd });
        const d = await r.json();
        if (d.ok) showToast(`✓ ${d.count}개 문서 업로드 완료 → ${d.dir}`, 4000);
        else showToast(`✗ 업로드 실패: ${d.error || '서버 오류'}`, 5000);
      } catch (e) {
        showToast(`✗ 네트워크 오류`, 5000);
      }
    });

    setInterval(pollDocumentsFolderUploadRequest, POLL_INTERVAL);

    /* ── Distance File 위젯 전용 파일 업로드 폴링 (.dst/.xlsx) ── */
    async function pollDistanceUploadRequest() {
      try {
        const r = await fetch('/upload-poll-distance?sid=' + SID);
        const d = await r.json();
        if (d.requested && (Date.now() - lastTriggered) > TRIGGER_COOLDOWN) {
          lastTriggered = Date.now();
          document.getElementById('distance-file-input').click();
        }
      } catch (_) {}
    }

    document.getElementById('distance-file-input').addEventListener('change', async function() {
      const file = this.files[0];
      this.value = '';
      if (!file) return;
      showToast(`거리행렬 업로드 중: ${file.name}`);
      const fd = new FormData();
      fd.append('file', file);
      try {
        const r = await fetch('/upload?sid=' + SID + '&kind=distance', { method:'POST', body:fd });
        const d = await r.json();
        if (d.filename) showToast(`✓ 거리행렬 업로드: ${d.filename}`, 4000);
        else            showToast(`✗ 실패: ${d.error || '서버 오류'}`, 5000);
      } catch (e) {
        showToast(`✗ 네트워크 오류`, 5000);
      }
    });

    setInterval(pollDistanceUploadRequest, POLL_INTERVAL);

    /* ── Network File 위젯 전용 파일 업로드 폴링 (.net/.pajek) ── */
    async function pollNetworkUploadRequest() {
      try {
        const r = await fetch('/upload-poll-network?sid=' + SID);
        const d = await r.json();
        if (d.requested && (Date.now() - lastTriggered) > TRIGGER_COOLDOWN) {
          lastTriggered = Date.now();
          document.getElementById('network-file-input').click();
        }
      } catch (_) {}
    }

    document.getElementById('network-file-input').addEventListener('change', async function() {
      const file = this.files[0];
      this.value = '';
      if (!file) return;
      showToast(`네트워크 파일 업로드 중: ${file.name}`);
      const fd = new FormData();
      fd.append('file', file);
      try {
        const r = await fetch('/upload?sid=' + SID + '&kind=network', { method:'POST', body:fd });
        const d = await r.json();
        if (d.filename) showToast(`✓ 네트워크 업로드: ${d.filename}`, 4000);
        else            showToast(`✗ 실패: ${d.error || '서버 오류'}`, 5000);
      } catch (e) {
        showToast(`✗ 네트워크 오류`, 5000);
      }
    });

    setInterval(pollNetworkUploadRequest, POLL_INTERVAL);

    /* ── Sentiment Analysis 위젯 전용 Custom dictionary 업로드 (Pos/Neg 두 슬롯) ── */
    async function pollSentPosUploadRequest() {
      try {
        const r = await fetch('/upload-poll-sent-pos?sid=' + SID);
        const d = await r.json();
        if (d.requested && (Date.now() - lastTriggered) > TRIGGER_COOLDOWN) {
          lastTriggered = Date.now();
          document.getElementById('sent-pos-file-input').click();
        }
      } catch (_) {}
    }
    document.getElementById('sent-pos-file-input').addEventListener('change', async function() {
      const file = this.files[0];
      this.value = '';
      if (!file) return;
      showToast(`Positive 사전 업로드: ${file.name}`);
      const fd = new FormData();
      fd.append('file', file);
      try {
        const r = await fetch('/upload?sid=' + SID + '&kind=sent_pos', { method:'POST', body:fd });
        const d = await r.json();
        if (d.filename) showToast(`✓ Positive 사전: ${d.filename}`, 4000);
        else            showToast(`✗ 실패: ${d.error || '서버 오류'}`, 5000);
      } catch (e) {
        showToast(`✗ 네트워크 오류`, 5000);
      }
    });
    setInterval(pollSentPosUploadRequest, POLL_INTERVAL);

    async function pollSentNegUploadRequest() {
      try {
        const r = await fetch('/upload-poll-sent-neg?sid=' + SID);
        const d = await r.json();
        if (d.requested && (Date.now() - lastTriggered) > TRIGGER_COOLDOWN) {
          lastTriggered = Date.now();
          document.getElementById('sent-neg-file-input').click();
        }
      } catch (_) {}
    }
    document.getElementById('sent-neg-file-input').addEventListener('change', async function() {
      const file = this.files[0];
      this.value = '';
      if (!file) return;
      showToast(`Negative 사전 업로드: ${file.name}`);
      const fd = new FormData();
      fd.append('file', file);
      try {
        const r = await fetch('/upload?sid=' + SID + '&kind=sent_neg', { method:'POST', body:fd });
        const d = await r.json();
        if (d.filename) showToast(`✓ Negative 사전: ${d.filename}`, 4000);
        else            showToast(`✗ 실패: ${d.error || '서버 오류'}`, 5000);
      } catch (e) {
        showToast(`✗ 네트워크 오류`, 5000);
      }
    });
    setInterval(pollSentNegUploadRequest, POLL_INTERVAL);

    /* ── Dataset 카탈로그 호출 폴링 (File 위젯 Dataset 버튼) ── */
    /* 분류(Classification) 전용 모달을 인페이지 오버레이로 표시 */
    function _ensureDatasetModal() {
      if (document.getElementById('dataset-modal-overlay')) return;
      const overlay = document.createElement('div');
      overlay.id = 'dataset-modal-overlay';
      overlay.style.cssText = 'position:fixed;inset:0;z-index:99999;'
        + 'background:rgba(0,0,0,0.55);display:none;'
        + 'align-items:center;justify-content:center;backdrop-filter:blur(2px);';
      overlay.innerHTML =
        '<div style="width:min(1100px,94vw);height:min(720px,90vh);'
        + 'background:#fff;border-radius:12px;'
        + 'box-shadow:0 20px 60px rgba(0,0,0,0.35);overflow:hidden;'
        + 'display:flex;flex-direction:column;">'
        + '<iframe id="dataset-modal-iframe" src="about:blank" '
        + 'style="border:0;width:100%;height:100%;display:block;"></iframe>'
        + '</div>';
      document.body.appendChild(overlay);
      overlay.addEventListener('click', function(e) {
        if (e.target === overlay) closeDatasetModal();
      });
    }

    /* 마지막에 모달을 연 카테고리 — dataset-selected 시 신호 파일 분기에 사용 */
    var _lastDatasetModalCategory = '';

    function openDatasetModal(category) {
      _ensureDatasetModal();
      _lastDatasetModalCategory = category || '';
      const overlay = document.getElementById('dataset-modal-overlay');
      const iframe = document.getElementById('dataset-modal-iframe');
      var url = '/datasets-catalog?_t=' + Date.now();
      if (category) url += '&cat=' + encodeURIComponent(category);
      iframe.src = url;
      overlay.style.display = 'flex';
    }

    function closeDatasetModal() {
      const overlay = document.getElementById('dataset-modal-overlay');
      if (overlay) {
        overlay.style.display = 'none';
        const iframe = document.getElementById('dataset-modal-iframe');
        if (iframe) iframe.src = 'about:blank';
      }
    }

    /* iframe 모달로부터 선택 결과 수신 */
    window.addEventListener('message', async function(ev) {
      const data = ev.data;
      if (!data || typeof data !== 'object') return;
      if (data.type === 'dataset-cancelled') {
        closeDatasetModal();
        return;
      }
      if (data.type === 'dataset-selected' && data.path) {
        try {
          // text 카테고리에서 열린 모달이면 kind=corpus → Corpus 위젯이 소비
          var kind = (_lastDatasetModalCategory === 'text') ? 'corpus' : 'data';
          var qs = 'sid=' + encodeURIComponent(SID)
                 + '&path=' + encodeURIComponent(data.path)
                 + '&kind=' + encodeURIComponent(kind);
          const r = await fetch('/dataset-select?' + qs, { method: 'POST' });
          const res = await r.json();
          if (res.ok) {
            showToast('✓ 데이터셋 적용: ' + (data.file || data.path), 3500);
            closeDatasetModal();
          } else {
            showToast('✗ 적용 실패: ' + (res.error || '서버 오류'), 5000);
          }
        } catch (e) {
          showToast('✗ 네트워크 오류', 5000);
        }
      }
    });

    async function pollDatasetRequest() {
      try {
        const r = await fetch('/dataset-poll?sid=' + SID);
        const d = await r.json();
        if (d.requested && (Date.now() - lastTriggered) > TRIGGER_COOLDOWN) {
          lastTriggered = Date.now();
          openDatasetModal(d.category || '');
        }
      } catch (_) {}
    }
    setInterval(pollDatasetRequest, POLL_INTERVAL);

    /* ── 내 PC 저장 폴링 (OWSave 위젯 → showSaveFilePicker 직접 호출, 모달 없음) ── */
    var _pcDownloadInflight = false;
    /* 위젯 인스턴스별 파일 핸들 캐시. key = widget_id (없으면 '__global__').
       Save Model 처럼 widget_id 를 보내는 위젯은 인스턴스별로 핸들이 분리되어
       새로 추가된 위젯이 앞 위젯의 핸들을 재사용하지 않는다. widget_id 가 없는
       Save Data 위젯은 전부 '__global__' 슬롯을 공유해 기존 동작을 유지. */
    var _pcWidgetHandles = {};      // {widget_id: {handle, basename}}

    /* 라벨에서 확장자 추출: "Tab-separated values (*.tab)" → ".tab" */
    function _extractExt(label) {
      var m = label.match(/\(\*([^)]+)\)/);
      return m ? m[1] : '';
    }

    async function pollPcDownload() {
      if (_pcDownloadInflight) return;
      try {
        const r = await fetch('/pc_download/check?sid=' + SID);
        const d = await r.json();
        if (!d || !d.ready || !d.files || !d.files.length) return;
        _pcDownloadInflight = true;
        console.log('[PCDL] signal detected:', d);
        // 위젯 인스턴스별 핸들 캐시 키 — widget_id 미전송(Save Data) 시 '__global__'
        var wid = d.widget_id || '__global__';
        var cached = _pcWidgetHandles[wid];
        // 1) 저장된 핸들로 자동 저장 시도 (force_new=false + 위젯별 basename 동일)
        if (!d.force_new && cached && cached.handle && cached.basename === d.basename) {
          console.log('[PCDL] PATH=cached_handle_reuse wid=' + wid);
          try {
            var perm = await cached.handle.queryPermission({ mode: 'readwrite' });
            if (perm === 'granted') {
              var savedName = cached.handle.name;
              var matched = null;
              for (var i = 0; i < d.files.length; i++) {
                var fext = _extractExt(d.files[i].label);
                if (fext && savedName.toLowerCase().endsWith(fext.toLowerCase())) {
                  matched = d.files[i]; break;
                }
              }
              if (matched) {
                var fr = await fetch('/pc_download/get?sid=' + SID + '&fname=' + encodeURIComponent(matched.filename) + '&cleanup=1');
                if (fr.ok) {
                  var blob = await fr.blob();
                  var writable = await cached.handle.createWritable();
                  await writable.write(blob);
                  await writable.close();
                  showToast('✓ 저장 완료: ' + savedName, 3000);
                  try { fetch('/pc_download/notify_saved?sid=' + SID + '&name=' + encodeURIComponent(savedName)); } catch(_) {}
                  _pcDownloadInflight = false;
                  return;
                }
              }
            }
          } catch (err) {
            delete _pcWidgetHandles[wid];
          }
        }
        // 2) showSaveFilePicker 직접 호출 (모달 없음)
        console.log('[PCDL] PATH=direct_picker wid=' + wid);
        await _directSavePicker(d.basename, d.files, !!d.force_new, wid);
      } catch(e) { console.error('[PCDL] poll error:', e); _pcDownloadInflight = false; }
    }
    setInterval(pollPcDownload, 1500);

    /* showSaveFilePicker 직접 호출 → 실패(브라우저 권한/미지원) 시 anchor 다운로드 폴백 */
    async function _directSavePicker(basename, files, forceNew, widgetId) {
      try {
        if (!window.showSaveFilePicker) throw new Error('not_supported');
        var types = files.map(function(f) {
          var ext = _extractExt(f.label);
          var desc = f.label.replace(/\s*\(\*[^)]+\)\s*$/, '');
          return { description: desc, accept: (function() { var o = {}; o['application/octet-stream'] = [ext]; return o; })() };
        });
        var defaultExt = _extractExt(files[0].label);
        var handle = await window.showSaveFilePicker({
          suggestedName: basename + defaultExt,
          types: types
        });
        var chosenName = handle.name || (basename + defaultExt);
        var matched = null;
        for (var i = 0; i < files.length; i++) {
          var fext = _extractExt(files[i].label);
          if (fext && chosenName.toLowerCase().endsWith(fext.toLowerCase())) {
            matched = files[i]; break;
          }
        }
        if (!matched) matched = files[0];
        var fr = await fetch('/pc_download/get?sid=' + SID + '&fname=' + encodeURIComponent(matched.filename) + '&cleanup=1');
        if (!fr.ok) throw new Error('파일 fetch 실패');
        var blob = await fr.blob();
        var writable = await handle.createWritable();
        await writable.write(blob);
        await writable.close();
        if (!forceNew) {
          // 위젯별 핸들 캐시에 저장 — widgetId 가 없으면 '__global__'(Save Data)
          var key = widgetId || '__global__';
          _pcWidgetHandles[key] = { handle: handle, basename: basename };
          try { fetch('/pc_download/notify_saved?sid=' + SID + '&name=' + encodeURIComponent(chosenName)); } catch(_) {}
        }
        showToast('✓ 저장 완료: ' + chosenName, 3000);
      } catch (err) {
        if (err.name === 'AbortError') {
          try { fetch('/pc_download/cleanup?sid=' + SID); } catch(_) {}
        } else {
          // 폴백: anchor 다운로드 (브라우저가 "저장 위치 묻기" 설정 켜져 있으면 다이얼로그 표시)
          try {
            var first = files[0];
            var fr2 = await fetch('/pc_download/get?sid=' + SID + '&fname=' + encodeURIComponent(first.filename) + '&cleanup=1');
            if (!fr2.ok) throw new Error('파일 fetch 실패');
            var blob2 = await fr2.blob();
            var url = URL.createObjectURL(blob2);
            var a = document.createElement('a');
            a.href = url; a.download = first.filename;
            document.body.appendChild(a); a.click(); document.body.removeChild(a);
            setTimeout(function() { URL.revokeObjectURL(url); }, 2000);
            if (!forceNew) {
              try { fetch('/pc_download/notify_saved?sid=' + SID + '&name=' + encodeURIComponent(first.filename)); } catch(_) {}
            }
            showToast('✓ 다운로드(폴백): ' + first.filename, 3000);
          } catch (err2) {
            showToast('저장 실패: ' + (err2.message || err2), 3000);
          }
        }
      } finally {
        _pcDownloadInflight = false;
      }
    }

    /* ── 토스트 ── */
    function showToast(msg, duration) {
      const t = document.getElementById('toast');
      t.textContent = msg;
      t.style.display = 'block';
      clearTimeout(t._timer);
      if (duration) t._timer = setTimeout(() => t.style.display = 'none', duration);
    }

    /* ── VNC 키 이벤트 전달 (서버 사이드 xdotool) ── */
    const _keyMap = {'=':'equal', '-':'minus', ' ':'space', '+':'plus'};
    async function sendKey(key, modifiers) {
      closeMenu(); closeLang();
      const xk = _keyMap[key] || key;
      const xkey = modifiers ? modifiers + '+' + xk : xk;
      try {
        await fetch('/sendkey?sid=' + SID + '&key=' + encodeURIComponent(xkey));
      } catch(_) {
        showToast((modifiers ? modifiers + '+' : '') + key, 2000);
      }
    }

    /* ── 문서 타이틀 메뉴 ── */
    function toggleMenu() {
      document.getElementById('menu-dropdown').classList.toggle('open');
      document.getElementById('lang-dropdown').classList.remove('open');
    }
    function closeMenu() {
      document.getElementById('menu-dropdown').classList.remove('open');
    }


    function openFileDialog() {
      closeMenu();
      document.getElementById('pc-file-input').click();
    }

    /* ── .ows 워크플로우 불러오기 ── */
    function openOwsDialog() {
      closeMenu();
      document.getElementById('ows-file-input').click();
    }
    document.getElementById('ows-file-input').addEventListener('change', async function() {
      const file = this.files[0];
      if (!file) return;
      this.value = '';
      // 기존 캔버스 덮어쓰기 X → 새 탭으로 추가 (Templates 의 wfAddTemplateTab 패턴과 동일)
      if (typeof window.wfAddFileTab === 'function') {
        await window.wfAddFileTab(file);
      } else {
        // fallback (구 동작): 현재 캔버스에 직접 로드
        showToast('워크플로우 불러오는 중...', 5000);
        const form = new FormData();
        form.append('file', file);
        try {
          const r = await fetch('/open-workflow?sid=' + SID, {method:'POST', body:form});
          const d = await r.json();
          if (d.ok) showToast('✓ ' + d.filename + ' 열기 완료', 2500);
          else showToast('오류: ' + (d.error || '알 수 없음'), 3000);
        } catch(e) { showToast('업로드 실패', 3000); }
      }
    });

    /* ── 워크플로우 저장 (OS 파일 저장 대화상자) ── */
    async function saveWorkflow() {
      closeMenu();

      // showSaveFilePicker: HTTPS 또는 localhost 환경에서만 동작
      // 반드시 사용자 제스처(클릭) 직후 호출해야 대화상자가 열림
      // → fetch 이후 호출 시 제스처 컨텍스트 만료로 대화상자 차단됨

      if (!window.isSecureContext || !window.showSaveFilePicker) {
        // 비보안 환경 또는 미지원 브라우저 → 다운로드 폴백
        showToast('저장 중...', 10000);
        await _downloadWorkflow();
        return;
      }

      // 1. 탐색기 저장 대화상자 즉시 열기
      let fileHandle;
      try {
        fileHandle = await window.showSaveFilePicker({
          suggestedName: 'workflow.ows',
          types: [{ description: 'Orange Workflow', accept: { 'application/octet-stream': ['.ows'] } }],
        });
      } catch(e) {
        if (e.name === 'AbortError') { showToast('저장 취소', 1500); return; }
        showToast('대화상자 오류: ' + e.message, 3000);
        return;
      }

      // 2. 대화상자 확인 후 서버에서 파일 내용 수신
      showToast('저장 중...', 10000);
      try {
        const r = await fetch('/save-workflow?sid=' + SID);
        if (!r.ok) {
          const d = await r.json().catch(() => ({}));
          showToast('저장 실패: ' + (d.error || r.status), 3000);
          return;
        }
        const blob = await r.blob();
        const writable = await fileHandle.createWritable();
        await writable.write(blob);
        await writable.close();
        showToast('✓ ' + fileHandle.name + ' 저장 완료', 3000);
      } catch(e) {
        showToast('저장 오류: ' + e.message, 3000);
      }
    }

    async function _downloadWorkflow() {
      try {
        const r = await fetch('/save-workflow?sid=' + SID);
        if (!r.ok) {
          const d = await r.json().catch(() => ({}));
          showToast('저장 실패: ' + (d.error || r.status), 3000);
          return;
        }
        const blob = await r.blob();
        const cd   = r.headers.get('Content-Disposition') || '';
        const m    = cd.match(/filename="(.+)"/);
        const fname = m ? m[1] : 'workflow.ows';
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = fname;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(a.href);
        showToast('✓ ' + fname + ' 다운로드 완료', 3000);
      } catch(e) {
        showToast('저장 오류', 3000);
      }
    }

    /* ── 언어 드롭다운 ── */
    function toggleLang() {
      var drop = document.getElementById('lang-dropdown');
      var btn  = document.getElementById('lang-btn');
      var rect = btn.getBoundingClientRect();
      drop.style.top   = (rect.bottom + 4) + 'px';
      drop.style.right = (window.innerWidth - rect.right) + 'px';
      drop.classList.toggle('open');
      document.getElementById('menu-dropdown').classList.remove('open');
    }
    function closeLang() {
      document.getElementById('lang-dropdown').classList.remove('open');
    }

    /* Templates 버튼 SVG 아이콘 (모든 언어 공통) */
    const _TPL_ICON = '<svg width="14" height="14" viewBox="0 0 16 16" fill="none"><rect x="2" y="2" width="5" height="5" rx="1" stroke="currentColor" stroke-width="1.6"/><rect x="9" y="2" width="5" height="5" rx="1" stroke="currentColor" stroke-width="1.6"/><rect x="2" y="9" width="5" height="5" rx="1" stroke="currentColor" stroke-width="1.6"/><rect x="9" y="9" width="5" height="5" rx="1" stroke="currentColor" stroke-width="1.6"/></svg>';
    /* Analysis-Datasets 버튼 SVG 아이콘 (데이터베이스 원통, 모든 언어 공통) */
    const _DS_ICON = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5v6c0 1.66 4.03 3 9 3s9-1.34 9-3V5"/><path d="M3 11v6c0 1.66 4.03 3 9 3s9-1.34 9-3v-6"/></svg>';
    const LANGS = {
      ko: {
        docTitle: '제목없음',
        mi: ['새 문서','불러오기','저장','사본 만들기','닫기'],
        btns: [_DS_ICON + 'Analysis-Datasets', _TPL_ICON + 'Templates'],
      },
      en: {
        docTitle: 'Untitled',
        mi: ['New','Open','Save','Save a Copy','Close'],
        btns: [_DS_ICON + 'Analysis-Datasets', _TPL_ICON + 'Templates'],
      },
      sl: {
        docTitle: 'Bez názvu',
        mi: ['Nový','Otvoriť','Uložiť','Uložiť kópiu','Zatvoriť'],
        btns: [_DS_ICON + 'Analysis-Datasets', _TPL_ICON + 'Templates'],
      },
    };

    function applyLangUI(code) {
      const d = LANGS[code];
      if (!d) return;
      document.getElementById('doc-title').textContent = d.docTitle;
      document.querySelectorAll('#menu-dropdown .mi').forEach((el,i) => {
        if (d.mi[i] !== undefined) el.textContent = d.mi[i];
      });
      const btns = document.querySelectorAll('#header-right .h-btn');
      btns.forEach((el,i) => { if (d.btns[i] !== undefined) el.innerHTML = d.btns[i]; });
      document.querySelectorAll('.li').forEach(el => el.classList.remove('active'));
      const active = document.querySelector(`.li[onclick="setLang('${code}')"]`);
      if (active) active.classList.add('active');
    }
    async function setLang(code) {
      closeLang();
      if (!LANGS[code]) return;
      try {
        showToast('언어 변경 중…', 0);
        const resp = await fetch('/set-language?sid=' + SID + '&lang=' + code);
        const d = await resp.json().catch(function() { return {ok: false}; });
        if (!resp.ok || !d.ok) {
          showToast('언어 변경 실패: ' + (d.error || resp.status), 3000);
          return;
        }
        /* /set-language 가 .app_ready 를 제거했으므로 → LOADING_PAGE 가 서빙됨 */
        window.location.href = '/?sid=' + SID + '&lang=' + code;
      } catch(e) {
        showToast('언어 변경 실패', 2000);
      }
    }
    /* 서버가 HTML 생성 시 언어 코드를 직접 삽입 — dropdown 은 스크립트 블록 이후에 위치하므로 DOM 완성 후 호출 */
    document.addEventListener('DOMContentLoaded', function() { applyLangUI('en'); });


    let zoomLevel = 100;

    /* ── 분석 데이터셋 카탈로그 — 인페이지 모달 ── */
    function openAnalysisDatasets() {
      // Dataset 버튼과 동일한 모달 구조 재사용
      _ensureDatasetModal();
      const overlay = document.getElementById('dataset-modal-overlay');
      const iframe  = document.getElementById('dataset-modal-iframe');
      iframe.src = '/analysis-datasets?_t=' + Date.now();
      overlay.style.display = 'flex';
    }

    /* ── Example Workflows 다이얼로그 열기 ── */
    async function openExampleWorkflows() {
      try {
        const r = await fetch('/open-example-workflows?sid=' + SID);
        const d = await r.json();
        if (!d.ok) showToast('오류: ' + (d.error || ''), 2500);
      } catch(e) { showToast('연결 오류', 2000); }
    }

    /* ── 교안 Workflows 갤러리 ── */
    var _lcActiveCat = 'All Templates';
    var _lcSearch = '';
    var _lcTemplates = [
      // 초등 Workflow: /upload_ows/elementary/*.ows lazy fetch (_ensureElementaryLoaded)
      { vendor:'중등', vendorIcon:'M', title:'기초 통계 분석',
         desc:'평균·분산·표준편차 등 기본 통계량 계산과 분포 시각화.',
         category:'중등 Workflow', badges:['중등','통계'], color:'#5B6BFF' },
      { vendor:'중등', vendorIcon:'M', title:'분류 모델 학습',
         desc:'로지스틱 회귀와 의사결정 트리로 분류 모델 학습·평가.',
         category:'중등 Workflow', badges:['중등','분류','ML'], color:'#9B6BFF' },
      { vendor:'중등', vendorIcon:'M', title:'클러스터링 실습',
         desc:'k-Means와 계층적 클러스터링으로 데이터 군집화.',
         category:'중등 Workflow', badges:['중등','클러스터링'], color:'#6BD9FF' },
      { vendor:'공통', vendorIcon:'C', title:'PCA 차원 축소',
         desc:'주성분 분석으로 고차원 데이터를 2D로 축소·시각화합니다.',
         category:'공통 Workflow', badges:['공통','PCA'], color:'#FF6B9C' },
      { vendor:'공통', vendorIcon:'C', title:'교차 검증',
         desc:'k-fold 교차 검증으로 모델 성능을 안정적으로 평가합니다.',
         category:'공통 Workflow', badges:['공통','평가'], color:'#A48BFF' },
      { vendor:'공통', vendorIcon:'C', title:'결측값 처리',
         desc:'결측값 대치·제거 전략별 비교.',
         category:'공통 Workflow', badges:['공통','데이터'], color:'#A0C8E8' },
      { vendor:'Getting Started', vendorIcon:'G', title:'Orange3 첫걸음',
         desc:'위젯·연결·실행의 기본 흐름을 가장 작게 보여주는 시작 워크플로우.',
         category:'Getting Started', badges:['시작','기본'], color:'#5BD3D9' },
      { vendor:'Getting Started', vendorIcon:'G', title:'파일 → 데이터 테이블',
         desc:'CSV/TAB 파일을 불러와 데이터 테이블 위젯에 연결합니다.',
         category:'Getting Started', badges:['시작','데이터'], color:'#FF6B6B' },
      { vendor:'베이직', vendorIcon:'B', title:'데이터 병합/조인',
         desc:'여러 데이터 테이블을 키 기준으로 병합합니다.',
         category:'베이직', badges:['베이직','데이터'], color:'#B8B8C8' },
    ];

    /* "베이직" 카테고리 — 컨테이너 내 실제 .ows 파일들 (lazy fetch) */
    var _lcBasicLoaded = false;
    var _lcBasicLoading = false;
    async function _ensureBasicLoaded() {
      if (_lcBasicLoaded || _lcBasicLoading) return;
      _lcBasicLoading = true;
      try {
        const r = await fetch('/basic_templates?sid=' + SID);
        const d = await r.json();
        if (d.ok && Array.isArray(d.items)) {
          // 베이직 카테고리 항목들 제거 후 실제 데이터로 교체
          _lcTemplates = _lcTemplates.filter(function(t) { return t.category !== '베이직'; });
          var palette = ['#5B6BFF','#FF6B9C','#FFB86B','#6BCB77','#9B6BFF','#6BD9FF','#FF6B6B','#A48BFF','#5BD3D9','#FF9B6B','#A0C8E8','#B8B8C8'];
          d.items.forEach(function(it, i) {
            _lcTemplates.push({
              vendor:'베이직', vendorIcon:'B',
              title: it.title || it.filename,
              desc: it.desc || '',
              category:'베이직',
              badges:['Workflow','.ows'],
              color: palette[i % palette.length],
              path: it.path,
              filename: it.filename,
              thumbnail: it.thumbnail || null
            });
          });
          _lcBasicLoaded = true;
        }
      } catch(_) {} finally { _lcBasicLoading = false; }
    }

    /* "초등 Workflow" 카테고리 — /upload_ows/elementary 내 .ows 파일들 (lazy fetch) */
    var _lcElementaryLoaded = false;
    var _lcElementaryLoading = false;
    async function _ensureElementaryLoaded() {
      if (_lcElementaryLoaded || _lcElementaryLoading) return;
      _lcElementaryLoading = true;
      try {
        const r = await fetch('/elementary_templates?sid=' + SID);
        const d = await r.json();
        if (d.ok && Array.isArray(d.items)) {
          _lcTemplates = _lcTemplates.filter(function(t) { return t.category !== '초등 Workflow'; });
          var palette = ['#FF9B6B','#FFB86B','#6BCB77','#5B6BFF','#FF6B9C','#9B6BFF','#6BD9FF','#FF6B6B'];
          d.items.forEach(function(it, i) {
            _lcTemplates.push({
              vendor:'초등', vendorIcon:'E',
              title: it.title || it.filename,
              desc: it.desc || '',
              category:'초등 Workflow',
              badges:['초등','.ows'],
              color: palette[i % palette.length],
              path: it.path,
              filename: it.filename,
              thumbnail: it.thumbnail || null
            });
          });
          _lcElementaryLoaded = true;
        }
      } catch(_) {} finally { _lcElementaryLoading = false; }
    }

    async function openLessonTemplates() {
      document.getElementById('lesson-modal').classList.add('open');
      _renderLessonGrid();
      // 모달 열릴 때 현재 활성 카테고리 데이터를 백그라운드 로드 후 재렌더
      if (_lcActiveCat === 'All Templates') {
        await Promise.all([_ensureBasicLoaded(), _ensureElementaryLoaded()]);
      } else if (_lcActiveCat === '베이직') {
        await _ensureBasicLoaded();
      } else if (_lcActiveCat === '초등 Workflow') {
        await _ensureElementaryLoaded();
      }
      _renderLessonGrid();
    }
    function closeLessonModal() {
      document.getElementById('lesson-modal').classList.remove('open');
    }

    function _renderLessonGrid() {
      var grid = document.getElementById('lesson-grid');
      var heading = document.getElementById('lesson-heading');
      // 카테고리 표시명 매핑 (data-cat 내부값 → 화면 표시 라벨)
      var _CAT_DISPLAY = { '베이직': 'Example Workflow' };
      heading.textContent = _CAT_DISPLAY[_lcActiveCat] || _lcActiveCat;
      var q = (_lcSearch || '').toLowerCase();
      var filtered = _lcTemplates.filter(function(t) {
        if (_lcActiveCat !== 'All Templates' && t.category !== _lcActiveCat) return false;
        if (q && (t.title.toLowerCase().indexOf(q) < 0) && (t.desc.toLowerCase().indexOf(q) < 0)) return false;
        return true;
      });
      if (filtered.length === 0) {
        grid.innerHTML = '<div style="grid-column:1/-1;padding:40px;color:#888;text-align:center;">결과 없음</div>';
        return;
      }
      var html = '';
      filtered.forEach(function(t, idx) {
        var titleEsc = (t.title||'').replace(/[<>]/g,'');
        var descEsc = (t.desc||'').replace(/[<>]/g,'');
        var vendorEsc = (t.vendor||'').replace(/[<>]/g,'');
        // 썸네일 SVG 가 있으면 흰 배경 + SVG 표시, 없으면 그라데이션 색상
        var thumbStyle, thumbInner = '';
        if (t.thumbnail) {
          thumbStyle = 'background:#fff;';
          thumbInner = '<img src="' + t.thumbnail + '" class="lc-thumb-svg" alt="">';
        } else {
          thumbStyle = 'background:linear-gradient(135deg,' + t.color + ' 0%,#1a1a1c 130%);';
        }
        html += '<div class="lc-card" data-idx="' + idx + '">';
        html += '  <div class="lc-thumb" style="' + thumbStyle + '">';
        html += thumbInner;
        html += '    <div class="lc-vendor"><span style="display:inline-block;width:14px;height:14px;border-radius:50%;background:' + t.color + ';"></span>' + vendorEsc + '</div>';
        html += '    <div class="lc-badges">';
        (t.badges || []).forEach(function(b) {
          html += '<span class="lc-badge">' + b.replace(/[<>]/g,'') + '</span>';
        });
        html += '    </div>';
        html += '  </div>';
        html += '  <div class="lc-card-title">' + titleEsc + '</div>';
        html += '  <div class="lc-card-desc">' + descEsc + '</div>';
        html += '</div>';
      });
      grid.innerHTML = html;
      grid.querySelectorAll('.lc-card').forEach(function(el) {
        el.addEventListener('click', function() {
          var idx = parseInt(el.getAttribute('data-idx'), 10);
          var t = filtered[idx];
          if (!t) return;
          // 베이직 템플릿: 워크플로우 탭바에 새 탭 추가 + 파일명 그대로 탭 타이틀 사용
          if (t.path) {
            closeLessonModal();
            if (typeof window.wfAddTemplateTab === 'function') {
              window.wfAddTemplateTab(t.path, t.title, t.filename);
            }
          } else {
            showToast('템플릿 선택: ' + t.title + ' (준비 중)', 2500);
          }
        });
      });
    }

    /* 모달 사이드바 / 검색 / 배경 클릭 핸들러 */
    setTimeout(function() {
      document.querySelectorAll('#lesson-sidebar .lc-cat').forEach(function(el) {
        el.addEventListener('click', async function() {
          document.querySelectorAll('#lesson-sidebar .lc-cat').forEach(function(x) {
            x.classList.remove('active');
          });
          el.classList.add('active');
          _lcActiveCat = el.getAttribute('data-cat');
          // 베이직/초등 Workflow 카테고리는 실제 .ows 파일 목록을 lazy fetch
          var grid = document.getElementById('lesson-grid');
          var needLoad = false;
          if (_lcActiveCat === 'All Templates') {
            needLoad = !_lcBasicLoaded || !_lcElementaryLoaded;
          } else if (_lcActiveCat === '베이직') {
            needLoad = !_lcBasicLoaded;
          } else if (_lcActiveCat === '초등 Workflow') {
            needLoad = !_lcElementaryLoaded;
          }
          if (needLoad) {
            grid.innerHTML = '<div style="grid-column:1/-1;padding:40px;color:#888;text-align:center;">로딩 중...</div>';
            if (_lcActiveCat === 'All Templates') {
              await _ensureBasicLoaded();
              await _ensureElementaryLoaded();
            } else if (_lcActiveCat === '베이직') {
              await _ensureBasicLoaded();
            } else if (_lcActiveCat === '초등 Workflow') {
              await _ensureElementaryLoaded();
            }
          }
          _renderLessonGrid();
        });
      });
      var s = document.getElementById('lesson-search');
      if (s) s.addEventListener('input', function(e) {
        _lcSearch = e.target.value || '';
        _renderLessonGrid();
      });
      var m = document.getElementById('lesson-modal');
      if (m) m.addEventListener('click', function(e) {
        if (e.target === m) closeLessonModal();
      });
    }, 100);

    /* ── 헤더/탭바/사이드바 클릭 시 noVNC iframe 키보드 포커스 보호 ──
       mousedown 의 기본 동작(포커스 이동)을 차단해 DEL 등 키 이벤트가
       noVNC iframe 에 계속 전달되도록 한다. click 이벤트는 영향 없음. */
    ['header-bar', 'wf-tabbar', 'sb-wrap'].forEach(function(id) {
      var el = document.getElementById(id);
      if (el) el.addEventListener('mousedown', function(e) {
        /* input/textarea 는 직접 포커스가 필요하므로 제외 */
        if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') return;
        e.preventDefault();
      });
    });

    /* ── noVNC iframe → Delete/BackSpace postMessage 수신 ──────────────────
       noVNC HTML의 x-del-intercept 스크립트가 capture 단계에서 키를 가로채
       부모(wrapper) 페이지로 postMessage 전달.
       Delete  → /tool?tool=delete 로 Qt QAction(remove-selected) 직접 트리거
                 (xdotool 우회: 창 포커스 변경 없이 Qt 이벤트 루프에서 안전 실행)
       BackSpace → /sendkey 유지 */
    window.addEventListener('message', function(e) {
      if (e.data && e.data.type === 'vnc-del') {
        try { fetch('/tool?sid=' + SID + '&tool=delete'); } catch(_) {}
      } else if (e.data && e.data.type === 'vnc-selectall') {
        try { fetch('/tool?sid=' + SID + '&tool=selectall'); } catch(_) {}
      } else if (e.data && e.data.type === 'vnc-reload') {
        location.reload();
      }
    });

    /* 부모 페이지에서도 F5 → 전체 페이지 새로고침 (브라우저 기본 동작 명시적 재호출) */
    document.addEventListener('keydown', function(e) {
      if (e.key === 'F5') {
        e.preventDefault();
        location.reload();
      }
    }, true);

    /* ── 바깥 클릭 시 드롭다운 닫기 ── */
    document.addEventListener('click', function(e) {
      if (!document.getElementById('menu-wrap').contains(e.target)) closeMenu();
      if (!document.getElementById('lang-wrap').contains(e.target) &&
          !document.getElementById('lang-dropdown').contains(e.target))  closeLang();
      if (!document.getElementById('sb-wrap').contains(e.target)) {
        document.querySelectorAll('.sb-drop').forEach(function(d) { d.classList.remove('sb-open'); });
      }
    });

    /* ── 좌하단 상태바 ── */
    let sbCurrentTool = 'select';
    function sbToggleDrop(id) {
      const drop = document.getElementById('sb-drop-' + id);
      const wasOpen = drop.classList.contains('sb-open');
      document.querySelectorAll('.sb-drop').forEach(function(d) { d.classList.remove('sb-open'); });
      if (!wasOpen) drop.classList.add('sb-open');
    }
    const _SELECT_SVG = '<path d="M3.5 3 L12.5 9 L8.5 10 L7.2 13.5 Z" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round" stroke-linecap="round" fill="none"/>';
    const _HAND_SVG = '<path d="M6 11V5C6 4.5 6.5 4 7 4S8 4.5 8 5V8M8 5V4C8 3.5 8.5 3 9 3S10 3.5 10 4V8M10 4.5V4C10 3.5 10.5 3 11 3S12 3.5 12 4V9M12 6V5.5C12 5 12.5 4.5 13 4.5S14 5 14 5.5V11C14 12.5 12 14 10 14H8C6.5 14 5.5 13 4.5 11.5L3 9.5C2.5 8.5 3.5 7.5 4.5 8L6 9" stroke="currentColor" stroke-width="1.1" stroke-linecap="round" stroke-linejoin="round" fill="none"/>';
    function sbTool(name) {
      sbCurrentTool = name;
      const ico = document.getElementById('sb-tool-ico');
      const overlay = document.getElementById('pan-overlay');
      ico.setAttribute('viewBox', '0 0 16 16');
      if (name === 'select') {
        ico.innerHTML = _SELECT_SVG;
        document.getElementById('sb-tool-btn').classList.remove('sb-active');
        overlay.style.display = 'none';
        sendKey('Escape', '');
      } else {
        ico.innerHTML = _HAND_SVG;
        document.getElementById('sb-tool-btn').classList.add('sb-active');
        overlay.style.display = 'block';
        overlay.style.cursor = 'grab';
        sendKey('h', '');
      }
      document.getElementById('sb-drop-tool').classList.remove('sb-open');
    }
    /* ── 미니맵 뷰포트 표시기 ── */
    const MINI_W = 280, MINI_H = 158;
    let mapPanX = 0, mapPanY = 0;  // indicator center offset from minimap center (px)

    function updateVpRect() {
      const r = document.getElementById('sb-vp-rect');
      if (!r) return;
      const iW = Math.round(MINI_W * 2 / 3 * 0.8);
      const iH = Math.round(MINI_H * 2 / 3 * 0.8);
      const cX = MINI_W / 2 + mapPanX;
      const cY = MINI_H / 2 + mapPanY;
      r.style.width  = iW + 'px';
      r.style.height = iH + 'px';
      r.style.left   = Math.max(0, Math.min(MINI_W - iW, cX - iW / 2)) + 'px';
      r.style.top    = Math.max(0, Math.min(MINI_H - iH, cY - iH / 2)) + 'px';
    }

    // 패닝 후 미니맵 표시기 위치 갱신 (VNC 좌표 기준)
    function applyMapPan(fx, fy, tx, ty) {
      const f = document.getElementById('vnc-frame');
      const vW = f.offsetWidth  || window.innerWidth;
      const vH = f.offsetHeight || (window.innerHeight - 83);
      mapPanX += (fx - tx) / vW * MINI_W;
      mapPanY += (fy - ty) / vH * MINI_H;
      updateVpRect();
    }

    function sbZoom(action) {
      var toolName = null;
      if (action === 'in') {
        zoomLevel = Math.min(400, zoomLevel + 10);
        toolName = 'zoomin';
      } else if (action === 'out') {
        zoomLevel = Math.max(10, zoomLevel - 10);
        toolName = 'zoomout';
      } else if (action === 'fit') {
        zoomLevel = 100; mapPanX = 0; mapPanY = 0;
        toolName = 'zoomreset';
      }
      if (toolName) {
        try { fetch('/tool?sid=' + SID + '&tool=' + toolName); } catch(_) {}
      }
      const pct = zoomLevel + '%';
      document.getElementById('sb-zoom-pct').textContent = pct;
      const inp = document.getElementById('sb-zoom-input');
      if (inp) inp.value = zoomLevel;
      document.getElementById('sb-drop-zoom').classList.remove('sb-open');
      updateVpRect();
    }
    function sbZoomSet(val) {
      const v = Math.min(400, Math.max(10, parseInt(val) || 100));
      zoomLevel = v;
      document.getElementById('sb-zoom-pct').textContent = v + '%';
      const inp = document.getElementById('sb-zoom-input');
      if (inp) inp.value = v;
      document.getElementById('sb-drop-zoom').classList.remove('sb-open');
      updateVpRect();
    }
    function sbFit() {
      zoomLevel = 100; mapPanX = 0; mapPanY = 0; _mmAnalyzed = false;
      try { fetch('/tool?sid=' + SID + '&tool=zoomreset'); } catch(_) {}
      document.getElementById('sb-zoom-pct').textContent = '100%';
      const inp = document.getElementById('sb-zoom-input');
      if (inp) inp.value = 100;
      updateVpRect();
    }
    async function sbShortcut(name) {
      const textBtn  = document.getElementById('sb-text-btn');
      const penBtn   = document.getElementById('sb-pen-btn');
      const pauseBtn = document.getElementById('sb-pause-btn');
      if (name === 'text') {
        const isActive = textBtn.classList.contains('sb-active');
        textBtn.classList.remove('sb-active');
        penBtn.classList.remove('sb-active');
        if (!isActive) {
          textBtn.classList.add('sb-active');
          // 현재 선택된 폰트 크기 함께 전송 → 텍스트 모드 + 폰트 크기 한번에 적용
          const sz = (typeof _ctFontSize === 'number') ? _ctFontSize : 16;
          try { await fetch('/tool?sid=' + SID + '&tool=text:' + sz); } catch(_) {}
        }
      } else if (name === 'pen') {
        const isActive = penBtn.classList.contains('sb-active');
        textBtn.classList.remove('sb-active');
        penBtn.classList.remove('sb-active');
        if (!isActive) {
          penBtn.classList.add('sb-active');
          try { await fetch('/tool?sid=' + SID + '&tool=pen'); } catch(_) {}
        }
      } else if (name === 'pause') {
        pauseBtn.classList.toggle('sb-active');
        try { await fetch('/tool?sid=' + SID + '&tool=pause'); } catch(_) {}
      }
    }

    /* ── T 버튼 롱프레스 → 폰트 크기 드롭다운 ── */
    let _ctFontSize = 16;          // 현재 선택된 폰트 크기 (px). Orange3 기본값과 일치.
    let _ctPressTimer = null;
    let _ctLongPressed = false;
    const _CT_LONG_PRESS_MS = 500;  // 500ms 이상 누르면 롱프레스

    function _ctOpenFontDrop() {
      const drop = document.getElementById('ct-font-drop');
      if (drop) drop.classList.add('open');
    }
    function _ctCloseFontDrop() {
      const drop = document.getElementById('ct-font-drop');
      if (drop) drop.classList.remove('open');
    }
    function _ctClearPressTimer() {
      if (_ctPressTimer) { clearTimeout(_ctPressTimer); _ctPressTimer = null; }
    }

    /* T 버튼: mousedown으로 타이머 시작, mouseup/leave로 취소
       - 짧은 클릭(< 500ms) → 일반 sbShortcut('text') 호출
       - 길게 누르기(>= 500ms) → 드롭다운 표시 */
    (function _ctInitTextBtn() {
      const btn = document.getElementById('sb-text-btn');
      if (!btn) return;
      btn.addEventListener('mousedown', function(e) {
        if (e.button !== 0) return;  // 좌클릭만
        _ctLongPressed = false;
        _ctClearPressTimer();
        _ctPressTimer = setTimeout(function() {
          _ctLongPressed = true;
          _ctOpenFontDrop();
        }, _CT_LONG_PRESS_MS);
      });
      btn.addEventListener('mouseup', _ctClearPressTimer);
      btn.addEventListener('mouseleave', function() {
        // mouseleave는 mousedown 도중 마우스가 벗어나면 fire — 타이머 취소
        _ctClearPressTimer();
      });
      btn.addEventListener('click', function(e) {
        if (_ctLongPressed) {
          // 롱프레스 후의 click 이벤트는 무시 (드롭다운만 열기)
          e.preventDefault();
          e.stopPropagation();
          _ctLongPressed = false;
          return;
        }
        sbShortcut('text');
      });
      btn.addEventListener('contextmenu', function(e) { e.preventDefault(); });
    })();

    /* 드롭다운 바깥 클릭 시 닫기 */
    document.addEventListener('click', function(e) {
      const drop = document.getElementById('ct-font-drop');
      const btn  = document.getElementById('sb-text-btn');
      if (!drop || !drop.classList.contains('open')) return;
      if (drop.contains(e.target) || (btn && btn.contains(e.target))) return;
      _ctCloseFontDrop();
    });

    /* info 버튼 — 캔버스 도구 사용 안내 */
    function ctShowInfo() {
      // 주의: WRAPPER_PAGE는 Python triple-quoted string이므로 줄바꿈은 반드시
      // 백슬래시 두 개 + n 으로 표기해야 함 (그래야 출력 JS에 \\n 으로 들어가
      // JS escape sequence로 해석됨). 단일 백슬래시는 Python이 실제 newline으로
      // 해석해 주석/문자열이 끊어져 SyntaxError 발생함.
      alert([
        'Orange3 캔버스 도구 안내',
        '',
        '• T (텍스트): 클릭하여 텍스트 주석 작성',
        '       → 길게 누르면 폰트 크기 선택 (12~24px)',
        '• 화살표: 캔버스에 화살표 주석 추가',
        '• II  (일시정지): 위젯 간 신호 전파 중단/재개 (Shift+F)',
        '• 문서: 새 탭으로 워크플로우 열기',
        '• i  (도움말): 이 안내 표시'
      ].join(String.fromCharCode(10)));
    }

    /* 폰트 크기 선택 — 텍스트 모드 활성화 + 선택 사이즈 적용 */
    async function ctPickFontSize(size) {
      _ctFontSize = size;
      // 선택 표시 갱신
      document.querySelectorAll('.ct-font-item').forEach(function(it) {
        it.classList.toggle('sel', parseInt(it.dataset.size, 10) === size);
      });
      _ctCloseFontDrop();
      // 텍스트 도구 활성 상태로 전환 (펜 비활성화)
      const textBtn = document.getElementById('sb-text-btn');
      const penBtn  = document.getElementById('sb-pen-btn');
      textBtn.classList.add('sb-active');
      penBtn.classList.remove('sb-active');
      try { await fetch('/tool?sid=' + SID + '&tool=text:' + size); } catch(_) {}
    }

    let sbMapOpen = true;
    let _mmTimer = null;
    let _mmAnalyzed = false;
    const _mmSid = 'test-sid';

    /* 스크린샷을 canvas API로 분석해 뷰포트 표시기 자동 배치 */
    function analyzeMinimapImg(imgEl) {
      var W = MINI_W, H = MINI_H;
      /* 헤더 영역(83px/1080px) 제외 */
      var skipTop = Math.round(83 / 1080 * H);
      var c = document.createElement('canvas');
      c.width = W; c.height = H;
      var ctx = c.getContext('2d');
      try {
        ctx.drawImage(imgEl, 0, 0, W, H);
        var d = ctx.getImageData(0, skipTop, W, H - skipTop).data;
      } catch(e) { return; }
      var minX = W, maxX = 0, minY = H, maxY = 0, found = false;
      for (var y = 0; y < H - skipTop; y++) {
        for (var x = 0; x < W; x++) {
          var i4 = (y * W + x) * 4;
          var r = d[i4], g = d[i4+1], b = d[i4+2];
          /* 흰색/밝은 회색 이외의 픽셀 = 위젯 */
          if (!(r > 230 && g > 230 && b > 230)) {
            if (x < minX) minX = x;
            if (x > maxX) maxX = x;
            var gy = y + skipTop;
            if (gy < minY) minY = gy;
            if (gy > maxY) maxY = gy;
            found = true;
          }
        }
      }
      if (found && (maxX - minX) > 10 && (maxY - minY) > 5) {
        /* 위젯 바운딩박스 중심으로 표시기 이동 */
        mapPanX = (minX + maxX) / 2 - W / 2;
        mapPanY = (minY + maxY) / 2 - H / 2;
      } else {
        /* 위젯 없음: 전체 캔버스 1/5 지점을 중심으로 */
        mapPanX = W / 5 - W / 2;
        mapPanY = H / 5 - H / 2;
      }
      updateVpRect();
    }

    async function sbFixView() {
      /* 선택 위젯 중심 이동, 없으면 전체 보기 */
      const btn = document.getElementById('sb-fixview-btn');
      if (btn) btn.classList.add('sb-active');
      const f = document.getElementById('vnc-frame');
      const vW = f.offsetWidth  || window.innerWidth;
      const vH = f.offsetHeight || (window.innerHeight - 83);
      let found = false;
      try {
        const resp = await fetch('/screenshot?sid=' + SID + '&t=' + Date.now());
        if (resp.ok) {
          const blob = await resp.blob();
          const bmpImg = new Image();
          const objUrl = URL.createObjectURL(blob);
          await new Promise(function(res) { bmpImg.onload = res; bmpImg.onerror = res; bmpImg.src = objUrl; });
          URL.revokeObjectURL(objUrl);
          const sw = bmpImg.naturalWidth, sh = bmpImg.naturalHeight;
          if (sw > 0 && sh > 0) {
            const cv = document.createElement('canvas');
            cv.width = sw; cv.height = sh;
            const cx2 = cv.getContext('2d');
            cx2.drawImage(bmpImg, 0, 0);
            /* Orange3 툴바 영역(약 83px/1080) 건너뜀 */
            const skipY = Math.round(83 * sh / 1080);
            const d = cx2.getImageData(0, skipY, sw, sh - skipY).data;
            let minX = sw, maxX = 0, minY = sh, maxY = 0;
            for (var py = 0; py < sh - skipY; py++) {
              for (var px2 = 0; px2 < sw; px2++) {
                var i4 = (py * sw + px2) * 4;
                var r = d[i4], g = d[i4+1], b = d[i4+2];
                /* 오렌지 선택 색상: #F47B20 ≈ rgb(244,123,32) */
                if (r > 195 && g > 55 && g < 165 && b < 85) {
                  if (px2 < minX) minX = px2;
                  if (px2 > maxX) maxX = px2;
                  var gy = py + skipY;
                  if (gy < minY) minY = gy;
                  if (gy > maxY) maxY = gy;
                  found = true;
                }
              }
            }
            if (found && (maxX - minX) > 8 && (maxY - minY) > 8) {
              var selCx = (minX + maxX) / 2;
              var selCy = (minY + maxY) / 2;
              /* 스크린샷 좌표 → iframe 좌표 변환 */
              var fx2 = Math.round(selCx * vW / sw);
              var fy2 = Math.round(selCy * vH / sh);
              var tx2 = Math.round(vW / 2);
              var ty2 = Math.round(vH / 2);
              await fetch('/pan?sid=' + SID + '&fx=' + fx2 + '&fy=' + fy2 + '&tx=' + tx2 + '&ty=' + ty2 + '&cur=select');
              _mmAnalyzed = false;
              setTimeout(_mmRefresh, 700);
            } else {
              found = false;
            }
          }
        }
      } catch(e) {}
      if (!found) sbFit();
      setTimeout(function() { if (btn) btn.classList.remove('sb-active'); }, 400);
    }

    function _mmRefresh() {
      var img = document.getElementById('sb-minimap-img');
      if (!img) return;
      if (!_mmAnalyzed) {
        img.onload = function() {
          img.style.display = 'block';  // 첫 로드 성공 시 표시
          if (!_mmAnalyzed) {
            _mmAnalyzed = true;
            analyzeMinimapImg(img);
          }
        };
      }
      img.src = '/screenshot?sid=' + _mmSid + '&t=' + Date.now();
    }
    function sbToggleMap() {
      sbMapOpen = !sbMapOpen;
      document.getElementById('sb-minimap').style.display = sbMapOpen ? 'flex' : 'none';
      document.getElementById('sb-map-btn').classList.toggle('sb-active', sbMapOpen);
      if (sbMapOpen) {
        _mmRefresh();
        if (!_mmTimer) _mmTimer = setInterval(_mmRefresh, 3000);
      } else {
        if (_mmTimer) { clearInterval(_mmTimer); _mmTimer = null; }
      }
    }
    // 초기 로드 5초 후 첫 갱신 (VNC 연결 안정화 대기) + 타이머 시작
    setTimeout(_mmRefresh, 5000);
    _mmTimer = setInterval(_mmRefresh, 2000);

    // VNC iframe 클릭(위젯 실행 등) 감지 → 1초 후 즉시 갱신
    // window blur = 사용자가 VNC iframe 쪽으로 포커스 이동한 시점
    (function() {
      var _mmClickTimer = null;
      window.addEventListener('blur', function() {
        if (!sbMapOpen) return;
        if (_mmClickTimer) clearTimeout(_mmClickTimer);
        _mmClickTimer = setTimeout(function() {
          _mmRefresh();
          // 위젯 창이 열리는 데 시간이 걸릴 수 있으므로 2초 후 한 번 더
          setTimeout(_mmRefresh, 2000);
          _mmClickTimer = null;
        }, 1000);
      });
    })();

    /* ── VNC 연결 상태 감시 → 미니맵 오버레이 제어 ── */
    /* /ready 엔드포인트 사용 (same-origin) — VNC URL 직접 fetch 시 HTTPS mixed content 차단 방지 */
    let _vncReachable = true;
    function _mmSetDisc(disc) {
      var el = document.getElementById('sb-minimap-disc');
      if (el) el.style.display = disc ? 'flex' : 'none';
    }
    async function _checkVncReachable() {
      try {
        var r = await fetch('/ready?sid=' + SID);
        var data = await r.json();
        var isReady = data.ready === true;
        if (isReady && !_vncReachable) { _vncReachable = true; _mmSetDisc(false); }
        else if (!isReady && _vncReachable) { _vncReachable = false; _mmSetDisc(true); }
      } catch(e) {}
      setTimeout(_checkVncReachable, 8000);
    }
    setTimeout(_checkVncReachable, 5000);

    /* ── 패닝 오버레이: 클릭&드래그로 캔버스 화면 중심 이동 ──
       mousedown 시 document 레벨 mousemove/mouseup 등록 → 빠른 드래그에도 이벤트 손실 없음
       mousemove (throttle) → 누적 이동분만큼 캔버스 드래그
       mouseup → 드래그 종료 + 리스너 해제 */
    (function() {
      const overlay = document.getElementById('pan-overlay');
      let isDragging = false;
      let lastX = 0, lastY = 0;
      let panInFlight = false;
      let lastPanMs = 0;
      const PAN_INTERVAL = 80;

      function onMove(e) {
        if (!isDragging) return;
        e.preventDefault();
        const now = Date.now();
        if (panInFlight || now - lastPanMs < PAN_INTERVAL) return;
        const frame = document.getElementById('vnc-frame');
        const rect  = frame.getBoundingClientRect();
        const mx = Math.round(e.clientX - rect.left);
        const my = Math.round(e.clientY - rect.top);
        if (Math.abs(mx - lastX) < 4 && Math.abs(my - lastY) < 4) return;
        const sx = lastX, sy = lastY;
        lastX = mx; lastY = my;
        panInFlight = true;
        lastPanMs = now;
        applyMapPan(sx, sy, mx, my);
        // Hand 드래그: 마우스 이동 방향과 반대로 viewport 스크롤 (콘텐츠가 마우스 따라옴)
        const dx = sx - mx;
        const dy = sy - my;
        fetch('/pan2?sid=' + SID + '&dx=' + dx + '&dy=' + dy)
          .then(function() { panInFlight = false; })
          .catch(function() { panInFlight = false; });
      }

      function onUp(e) {
        if (!isDragging) return;
        isDragging = false;
        overlay.style.cursor = 'grab';
        document.removeEventListener('mousemove', onMove, true);
        document.removeEventListener('mouseup',   onUp,   true);
      }

      overlay.addEventListener('mousedown', function(e) {
        if (e.button !== 0) return;
        e.preventDefault();
        isDragging = true;
        const frame = document.getElementById('vnc-frame');
        const rect  = frame.getBoundingClientRect();
        lastX = Math.round(e.clientX - rect.left);
        lastY = Math.round(e.clientY - rect.top);
        overlay.style.cursor = 'grabbing';
        document.addEventListener('mousemove', onMove, true);
        document.addEventListener('mouseup',   onUp,   true);
      });
    })();

    /* ── 미니맵 클릭/드래그 → 메인 뷰 패닝 (이벤트 완전 격리) ── */
    (function() {
      const mOverlay = document.getElementById('sb-minimap-overlay');
      let isDragging  = false;
      let panInFlight = false;   // xdotool 시퀀스 진행 중 여부
      let lastPanMs   = 0;       // 마지막 pan 전송 시각
      const PAN_INTERVAL = 100;  // scroll 이벤트는 drag보다 가벼움

      function miniPan(mx, my) {
        const now = Date.now();
        if (panInFlight || now - lastPanMs < PAN_INTERVAL) return;
        const f = document.getElementById('vnc-frame');
        const vW = f.offsetWidth  || window.innerWidth;
        const vH = f.offsetHeight || (window.innerHeight - 83);
        const dX = (mx - MINI_W / 2 - mapPanX) / MINI_W * vW;
        const dY = (my - MINI_H / 2 - mapPanY) / MINI_H * vH;
        const fx = Math.round(vW / 2 + dX);
        const fy = Math.round(vH / 2 + dY);
        const tx = Math.round(vW / 2);
        const ty = Math.round(vH / 2);
        if (Math.abs(fx - tx) < 4 && Math.abs(fy - ty) < 4) return;
        const cfx = Math.max(0, Math.min(4096, fx));
        const cfy = Math.max(0, Math.min(4096, fy));
        applyMapPan(cfx, cfy, tx, ty);
        panInFlight = true;
        lastPanMs   = now;
        fetch('/scroll?sid=' + SID + '&fx=' + cfx + '&fy=' + cfy + '&tx=' + tx + '&ty=' + ty)
          .then(function()  { panInFlight = false; })
          .catch(function() { panInFlight = false; });
      }

      function stopDrag() {
        if (!isDragging) return;
        isDragging = false;
        mOverlay.classList.remove('dragging');
        document.removeEventListener('mousemove', onMove, true);
        document.removeEventListener('mouseup',   onUp,   true);
      }

      function onMove(e) {
        e.stopPropagation(); e.preventDefault();
        const br = mOverlay.getBoundingClientRect();
        miniPan(e.clientX - br.left, e.clientY - br.top);
      }
      function onUp(e) {
        e.stopPropagation();
        stopDrag();
      }

      mOverlay.addEventListener('mousedown', function(e) {
        if (e.button !== 0) return;
        e.preventDefault(); e.stopPropagation();
        isDragging = true;
        mOverlay.classList.add('dragging');
        document.addEventListener('mousemove', onMove, true);
        document.addEventListener('mouseup',   onUp,   true);
        const br = mOverlay.getBoundingClientRect();
        miniPan(e.clientX - br.left, e.clientY - br.top);
      });

      // 미니맵 내 다른 이벤트가 외부로 전파되지 않도록 차단
      ['click','dblclick','contextmenu','mouseup','mousemove'].forEach(function(t) {
        mOverlay.addEventListener(t, function(e) { e.stopPropagation(); e.preventDefault(); });
      });

      // iframe 포커스 이동 시 드래그 상태 초기화
      window.addEventListener('blur', stopDrag);
    })();

    // 초기 뷰포트 표시기 렌더링
    updateVpRect();

    /* ── 워크플로우 탭 바 (단일 세션 / save-load 방식) ── */
    (function() {
      /* 빈 Orange3 워크플로우 XML */
      var EMPTY_OWS = '<?xml version="1.0" encoding="utf-8"?>' +
        '<scheme version="2.0" title="" description="">' +
        '<nodes /><links /><annotations /><thumbnail /></scheme>';

      var tabs      = [];   /* { title, blob } */
      var active    = 0;
      var busy      = false;
      var wfCounter = 0;   /* 탭 생성 누적 카운터 */

      /* "Unsaved Workflow" / "Unsaved Workflow (n)" 레이블 */
      function tabLabel(n) {
        return n === 1 ? 'Unsaved Workflow' : 'Unsaved Workflow (' + n + ')';
      }

      /* 기본(미저장) 제목인지 판별 — 언어별 docTitle + 빈 문자열 */
      var _DEFAULT_TITLES = Object.keys(LANGS).map(function(k) { return LANGS[k].docTitle; });
      function isDefaultTitle(t) {
        return !t || _DEFAULT_TITLES.indexOf(t) >= 0;
      }

      function render() {
        var bar = document.getElementById('wf-tabbar');
        bar.innerHTML = '';
        tabs.forEach(function(tab, i) {
          var el = document.createElement('div');
          el.className = 'wf-tab' + (i === active ? ' wf-active' : '');
          if (busy && i === active) el.style.opacity = '0.6';

          var titleEl = document.createElement('span');
          titleEl.className = 'wf-tab-title';
          titleEl.textContent = tab.title || 'Unsaved Workflow';
          el.appendChild(titleEl);

          if (i === active) {
            var closeEl = document.createElement('span');
            closeEl.className = 'wf-tab-close';
            closeEl.textContent = '✕';
            closeEl.addEventListener('click', (function(idx) {
              return function(e) { e.stopPropagation(); wfConfirmClose(idx); };
            })(i));
            el.appendChild(closeEl);
          } else {
            var dotEl = document.createElement('span');
            dotEl.className = 'wf-tab-dot';
            dotEl.textContent = '·';
            el.appendChild(dotEl);
          }

          el.addEventListener('click', (function(idx) {
            return function() { wfSwitch(idx); };
          })(i));
          bar.appendChild(el);
        });

        var addBtn = document.createElement('div');
        addBtn.className = 'wf-tab-add';
        addBtn.textContent = '+';
        addBtn.title = '새 워크플로우';
        addBtn.addEventListener('click', wfAddTab);
        bar.appendChild(addBtn);
      }

      /* 현재 탭 상태를 서버에서 저장해 blob에 보관
         서버가 최대 10초 대기하므로 타임아웃 없이 완료를 기다림 (데이터 유실 방지)
         busy 영구 잠금은 호출 측 try/finally 에서 보장 */
      async function saveCurrent() {
        try {
          var t = document.getElementById('doc-title').textContent;
          if (!isDefaultTitle(t)) tabs[active].title = t;
          var r = await fetch('/save-workflow?sid=' + SID);
          if (r && r.ok) tabs[active].blob = await r.blob();
        } catch(e) {}
      }

      /* blob 또는 빈 캔버스를 Orange3에 로드 */
      async function loadTab(tab) {
        _mmAnalyzed = false; mapPanX = 0; mapPanY = 0; updateVpRect();
        var blob = tab.blob
          ? tab.blob
          : new Blob([EMPTY_OWS], {type: 'text/xml'});
        var fname = (tab.title || 'workflow').replace(/[^\w\-_. ]/g, '_') + '.ows';
        var fd = new FormData();
        fd.append('file', blob, fname);
        try {
          await fetch('/open-workflow?sid=' + SID, {method:'POST', body:fd});
          /* 왓처 주기 0.8s + Qt 처리 시간 보장 */
          await new Promise(function(res) { setTimeout(res, 900); });
          document.getElementById('doc-title').textContent = tab.title;
        } catch(e) {}
        /* 탭 전환 직후 미니맵 즉시 갱신 (1.2s, 2.5s 두 번 연속) */
        setTimeout(_mmRefresh, 1200);
        setTimeout(_mmRefresh, 2500);
      }

      /* 탭 전환 — try/finally 로 busy 항상 해제 */
      async function wfSwitch(toIdx) {
        if (busy || toIdx === active) return;
        busy = true; render();
        try {
          await saveCurrent();
          active = toIdx; render();
          await loadTab(tabs[active]);
        } finally {
          busy = false; render();
        }
      }

      /* 새 탭 — try/finally 로 busy 항상 해제 */
      async function wfAddTab() {
        if (busy) return;
        if (tabs.length >= 8) { showToast('탭은 최대 8개까지 사용할 수 있습니다.', 2500); return; }
        busy = true; render();
        try {
          await saveCurrent();
          wfCounter++;
          tabs.push({ title: tabLabel(wfCounter), blob: null });
          active = tabs.length - 1; render();
          await loadTab(tabs[active]);
        } finally {
          busy = false; render();
        }
      }

      /* 탭 닫기 확인 모달 */
      var _closeModalIdx = -1;

      function wfConfirmClose(idx) {
        if (busy || tabs.length === 1) return;
        _closeModalIdx = idx;
        var name = tabs[idx].title || 'Unsaved Workflow';
        document.getElementById('close-modal-wf-name').textContent = name;
        document.getElementById('close-modal').classList.add('open');
      }

      function modalCancel() {
        document.getElementById('close-modal').classList.remove('open');
        _closeModalIdx = -1;
      }

      async function modalSave() {
        document.getElementById('close-modal').classList.remove('open');
        var idx = _closeModalIdx;
        _closeModalIdx = -1;
        if (idx < 0) return;
        /* 활성 탭이면 메뉴 Save와 동일한 저장 대화상자 실행 후 탭 닫기 */
        if (idx === active) {
          await saveWorkflow();
        }
        await wfClose(idx, false);
      }

      async function modalNo() {
        document.getElementById('close-modal').classList.remove('open');
        var idx = _closeModalIdx;
        _closeModalIdx = -1;
        if (idx < 0) return;
        /* 저장 없이 탭 닫기 */
        await wfClose(idx, false);
      }

      /* 탭 닫기 — try/finally 로 busy 항상 해제 */
      async function wfClose(idx, doSave) {
        if (busy || tabs.length === 1) return;
        busy = true; render();
        try {
          if (idx === active) {
            if (doSave) await saveCurrent();
            tabs.splice(idx, 1);
            active = Math.min(active, tabs.length - 1);
            render();
            await loadTab(tabs[active]);
          } else {
            tabs.splice(idx, 1);
            if (active > idx) active--;
            render();
          }
        } finally {
          busy = false; render();
        }
      }

      /* doc-title 변경 → 활성 탭 제목 동기화 (실제 파일명일 때만 덮어씀) */
      var docTitleEl = document.getElementById('doc-title');
      new MutationObserver(function() {
        if (!busy && tabs[active]) {
          var t = docTitleEl.textContent;
          if (!isDefaultTitle(t)) {
            tabs[active].title = t;
            render();
          }
        }
      }).observe(docTitleEl, { childList:true, characterData:true, subtree:true });

      /* 초기화 */
      wfCounter = 1;
      tabs = [{ title: tabLabel(1), blob: null }];
      render();

      /* 베이직 템플릿을 새 탭으로 추가 — blob 을 컨테이너에서 fetch 후 탭에 적재 */
      async function wfAddTemplateTab(path, title, filename) {
        if (busy) return;
        if (tabs.length >= 8) { showToast('탭은 최대 8개까지 사용할 수 있습니다.', 2500); return; }
        busy = true; render();
        try {
          await saveCurrent();
          var r = await fetch('/template_blob?sid=' + SID + '&path=' + encodeURIComponent(path));
          if (!r.ok) throw new Error('템플릿 로드 실패');
          var blob = await r.blob();
          // 파일명을 그대로 탭 타이틀로 사용 (확장자 제거)
          var tabTitle = title || (filename || 'workflow').replace(/\.ows$/i, '');
          tabs.push({ title: tabTitle, blob: blob });
          active = tabs.length - 1; render();
          await loadTab(tabs[active]);
        } catch(e) {
          showToast('템플릿 열기 실패: ' + (e.message || e), 3000);
        } finally {
          busy = false; render();
        }
      }

      /* 사용자 선택 파일(.ows)을 새 탭으로 추가 — Open 메뉴에서 사용 */
      async function wfAddFileTab(file) {
        if (!file) return;
        if (busy) return;
        if (tabs.length >= 8) { showToast('탭은 최대 8개까지 사용할 수 있습니다.', 2500); return; }
        busy = true; render();
        try {
          await saveCurrent();
          var tabTitle = (file.name || 'workflow').replace(/\.ows$/i, '');
          tabs.push({ title: tabTitle, blob: file });
          active = tabs.length - 1; render();
          await loadTab(tabs[active]);
          showToast('✓ ' + file.name + ' 새 탭에서 열림', 2500);
        } catch(e) {
          showToast('파일 열기 실패: ' + (e.message || e), 3000);
        } finally {
          busy = false; render();
        }
      }

      /* 모달 함수 전역 노출 (onclick 속성에서 접근 가능하도록) */
      window.modalSave        = modalSave;
      window.modalNo          = modalNo;
      window.modalCancel      = modalCancel;
      window.wfAddTab         = wfAddTab;
      window.wfAddTemplateTab = wfAddTemplateTab;
      window.wfAddFileTab     = wfAddFileTab;
      /* 메뉴의 "닫기" 항목 전용: 현재 활성 탭의 X 클릭과 동일 동작 */
      window.wfCloseActive    = function() { wfConfirmClose(active); };
    })();
  