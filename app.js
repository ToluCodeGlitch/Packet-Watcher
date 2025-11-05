// Simple Packet Guardian front-end detector (client-side)
// Parses lines like:
// [2025-11-04 09:00:12] SRC=192.168.10.22 DST=104.27.122.12 PROTO=HTTP SIZE=512
// or simple CSV lines: SRC,DST,SIZE
(function(){
  const fileInput = document.getElementById('fileInput');
  const runBtn = document.getElementById('runBtn');
  const logArea = document.getElementById('logArea');
  const alertsDiv = document.getElementById('alerts');
  const summary = document.getElementById('summary');
  const tbody = summary.querySelector('tbody');
  const downloadReport = document.getElementById('downloadReport');

  const timeWindowInput = document.getElementById('timeWindow');
  const byteThresholdInput = document.getElementById('byteThreshold');
  const increasingCountInput = document.getElementById('increasingCount');

  fileInput.addEventListener('change', (e)=>{
    const f = e.target.files[0];
    if(!f) return;
    const reader = new FileReader();
    reader.onload = ()=> logArea.value = reader.result;
    reader.readAsText(f);
  });

  function parseLogs(text){
    const lines = text.split('\n').map(l=>l.trim()).filter(Boolean);
    const parsed = [];
    const reBracket = /SRC=(\S+)\s+DST=(\S+)\s+PROTO=\S+\s+SIZE=(\d+)/i;
    const reCsv = /^(\S+),(\S+),(\d+)$/;
    for(const l of lines){
      let m = reBracket.exec(l);
      if(m) {
        parsed.push({src:m[1], dst:m[2], size:parseInt(m[3],10), raw:l});
        continue;
      }
      let c = reCsv.exec(l);
      if(c){
        parsed.push({src:c[1], dst:c[2], size:parseInt(c[3],10), raw:l});
        continue;
      }
      // attempt simple fields
      const parts = l.split(/\s+/);
      const src = parts.find(p=>p.startsWith('SRC='))?.split('=')[1];
      const dst = parts.find(p=>p.startsWith('DST='))?.split('=')[1];
      const size = parts.find(p=>p.startsWith('SIZE='))?.split('=')[1];
      if(src && dst && size) parsed.push({src,dst,size:parseInt(size,10), raw:l});
    }
    return parsed;
  }

  function detectFlows(records, opts){
    // flows keyed by "src|dst"
    const flows = {};
    const now = Date.now()/1000;
    for(const r of records){
      const key = r.src + '|' + r.dst;
      if(!flows[key]) flows[key] = {src:r.src, dst:r.dst, sizes: [], timestamps: []};
      // For demo we don't have timestamps in every log line; assume sequential 1s apart if none
      flows[key].timestamps.push(now + flows[key].timestamps.length);
      flows[key].sizes.push(r.size);
    }

    const alerts = [];
    for(const k in flows){
      const f = flows[k];
      // total bytes in window = sum last N seconds; in this simple front-end we just sum all sizes
      const total = f.sizes.reduce((a,b)=>a+b,0);
      if(total >= opts.byteThreshold){
        alerts.push({src:f.src,dst:f.dst,bytes:total, reason:'bytes > threshold'});
        continue;
      }
      // check consecutive increasing sizes
      const count = opts.increasingCount;
      if(f.sizes.length >= count){
        // look for any run of 'count' strictly increasing sizes
        for(let i=0;i<=f.sizes.length-count;i++){
          let inc=true;
          for(let j=0;j<count-1;j++){
            if(!(f.sizes[i+j] < f.sizes[i+j+1])) { inc=false; break; }
          }
          if(inc) { alerts.push({src:f.src,dst:f.dst,bytes:total,reason:`${count} increasing packets`}); break; }
        }
      }
    }
    return alerts;
  }

  function showAlerts(arr){
    alertsDiv.innerHTML = '';
    tbody.innerHTML = '';
    if(arr.length===0){
      alertsDiv.innerHTML = '<div class="alert">✅ No suspicious flows detected.</div>';
      summary.hidden = true;
      downloadReport.disabled = true;
      return;
    }
    for(const a of arr){
      const d = document.createElement('div');
      d.className='alert';
      d.textContent = `⚠️ ALERT: ${a.src} → ${a.dst} — ${a.reason} (bytes=${a.bytes})`;
      alertsDiv.appendChild(d);

      const tr = document.createElement('tr');
      tr.innerHTML = `<td>${a.src}</td><td>${a.dst}</td><td>${a.bytes}</td><td>${a.reason}</td>`;
      tbody.appendChild(tr);
    }
    summary.hidden = false;
    downloadReport.disabled = false;
  }

  runBtn.addEventListener('click', ()=>{
    const raw = logArea.value.trim();
    if(!raw){ alert('Paste logs or upload a file first.'); return; }
    const records = parseLogs(raw);
    if(records.length===0){ alert('No parsable log lines found. Use the sample format: SRC=1.2.3.4 DST=5.6.7.8 PROTO=HTTP SIZE=512'); return; }
    const opts = {
      timeWindow: Number(timeWindowInput.value || 60),
      byteThreshold: Number(byteThresholdInput.value || 1000000),
      increasingCount: Number(increasingCountInput.value || 3)
    };
    const alerts = detectFlows(records, opts);
    showAlerts(alerts);
  });

  downloadReport.addEventListener('click', ()=>{
    // make CSV from table
    const rows = [['Source','Destination','Bytes','Reason']];
    tbody.querySelectorAll('tr').forEach(tr=>{
      const cols = Array.from(tr.querySelectorAll('td')).map(td=>td.textContent);
      rows.push(cols);
    });
    const csv = rows.map(r=>r.map(c=>`"${c.replace(/"/g,'""')}"`).join(',')).join('\n');
    const blob = new Blob([csv], {type:'text/csv'});
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'packet-guardian-report.csv';
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  });

  // insert example logs
  document.addEventListener('DOMContentLoaded', ()=>{
    const sample = `[2025-11-04 09:00:12] SRC=192.168.10.22 DST=8.8.8.8 PROTO=DNS SIZE=84
[2025-11-04 09:00:13] SRC=192.168.10.22 DST=104.27.122.12 PROTO=HTTP SIZE=512
[2025-11-04 09:00:14] SRC=192.168.10.22 DST=104.27.122.12 PROTO=HTTP SIZE=525
[2025-11-04 09:00:15] SRC=192.168.10.22 DST=104.27.122.12 PROTO=HTTP SIZE=540
[2025-11-04 09:00:16] SRC=192.168.10.22 DST=104.27.122.12 PROTO=HTTP SIZE=560
[2025-11-04 09:00:18] SRC=192.168.10.22 DST=104.27.122.12 PROTO=HTTP SIZE=1200
[2025-11-04 09:00:19] SRC=192.168.10.22 DST=104.27.122.12 PROTO=HTTP SIZE=1300
[2025-11-04 09:00:20] SRC=192.168.10.22 DST=104.27.122.12 PROTO=HTTP SIZE=1500
[2025-11-04 09:00:21] SRC=192.168.10.22 DST=104.27.122.12 PROTO=HTTP SIZE=1900
[2025-11-04 09:00:22] SRC=192.168.10.22 DST=104.27.122.12 PROTO=HTTP SIZE=2000`;
    logArea.value = sample;
  });
})();
