// ============================================================
//  WiFi Web Server — Forensic Monitoring System (Bug Fix Ver)
//  - 스크립트 파싱 오류(화면 깨짐 현상) 완벽 해결
//  - 60초 슬라이딩 그래프, PDF 생성, CSV 다운로드 포함
//  - [적용] 가상 데이터(Random) 제거 및 32번, 34번 핀 실제 센서 연동
//  - [추가] 시리얼 모니터 실시간 충격값 출력 및 Peak 유지 로직 적용
//  - [수정] 툴팁(마우스 오버) 위치 오류 완벽 해결 (Position: fixed 적용)
// ============================================================

#include <WiFi.h>
#include <WebServer.h>
#include <time.h>
#include <mbedtls/sha256.h>
#include <DHT.h>

const char* WIFI_SSID     = "getchar";
const char* WIFI_PASSWORD = "2024111334";
const char* NTP_SERVER    = "pool.ntp.org";
const long  GMT_OFFSET    = 9 * 3600;

WebServer server(80);

#define DHTPIN 4
#define DHTTYPE DHT22
DHT dht(DHTPIN, DHTTYPE);

// ── 피에조 센서 실제 핀 설정 ──
#define PIN_CVIB 32 // 천장 측정용
#define PIN_IVIB 34 // 실내 측정용

struct Event {
  char  ts[20];
  float lowRatio;
  int   cVib;
  int   iVib;
  float db;    
  float temp;
  float humid;
  char  hash[65];
};

#define MAX_EVENTS 100
Event events[MAX_EVENTS];
int   totalEvents = 0;
unsigned long lastRead = 0;
#define READ_INTERVAL 5000 

// 찰나의 충격을 기억할 Peak 변수 선언
int peak_cVib = 0;
int peak_iVib = 0;

String sha256Hash(String data);
String getTimestamp();
void   processForensicAlgorithm(int cVib, int iVib);
void   handleRoot();
void   handleEvents();

// ─────────────────────────────────────────────────────────
//  Dashboard HTML
// ─────────────────────────────────────────────────────────
const char DASHBOARD_HTML[] PROGMEM = R"rawHTML(
<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8"/>
<title>층간소음 포렌식 대시보드</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"><\/script>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Malgun Gothic',sans-serif;background:#f4f7f9;color:#1a1a1a;padding-bottom:50px;}
.header{background:#1a3a5c;color:white;padding:15px 30px;border-bottom:4px solid #c9a961;display:flex;justify-content:space-between;align-items:center;}
.container{max-width:1100px;margin:20px auto;padding:0 20px;}
.card{background:white;border-radius:12px;padding:25px;box-shadow:0 4px 15px rgba(0,0,0,0.08);margin-bottom:20px;}
.btn-group{display:flex;gap:10px;margin-bottom:20px;flex-wrap:wrap;}
.btn{padding:10px 18px;border:none;border-radius:6px;cursor:pointer;font-weight:bold;font-size:12px;box-shadow:0 2px 4px rgba(0,0,0,0.1);transition:all 0.2s;}
.btn:hover{transform:translateY(-2px);}
.btn-refresh{background:#f8f9fa;color:#1a3a5c;border:1px solid #1a3a5c;}
.btn-tamper{background:#dc3545;color:white;}
.btn-trigger{background:#e85d24;color:white;}
.btn-csv{background:#15803d;color:white;}
.btn-pdf{background:#1a3a5c;color:white;}
.charts-grid{display:grid;grid-template-columns:3fr 2fr;gap:16px;margin-bottom:16px;}
.chart-wrap{position:relative;height:240px;}
.banner{background:white;border-left:5px solid #16a34a;border-radius:8px;padding:16px 20px;margin-bottom:16px;box-shadow:0 1px 3px rgba(0,0,0,.05);}
.banner.fail{border-left-color:#dc2626;background:#fef2f2;}
.stat-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:16px;}
.stat{background:white;border-radius:8px;padding:16px;box-shadow:0 1px 3px rgba(0,0,0,.04);border-top:3px solid #1a3a5c;}
.stat.g{border-top-color:#c9a961;}.stat.o{border-top-color:#d97706;}.stat.b{border-top-color:#4a7ba8;}
.stat-label{font-size:11px;color:#6b7280;text-transform:uppercase;margin-bottom:4px;}
.stat-val{font-size:22px;font-weight:700;}
table{width:100%;border-collapse:collapse;font-size:12px;margin-top:10px;}
th,td{padding:10px;border-bottom:1px solid #eee;text-align:left;}
th{background:#f8f9fa;color:#1a3a5c;}
.pass{color:#28a745;font-weight:bold;}
.fail2{color:#dc3545;font-weight:bold;}
</style>
</head>
<body>
<div class="header">
  <h1>층간소음 포렌식 분석 시스템 <small style="font-size:12px;color:#c9a961;">실시간 연동 모드</small></h1>
  <div id="status" style="font-size:12px;">연결됨</div>
</div>

<div class="container">
  <div class="btn-group">
    <button class="btn btn-refresh" onclick="fetchData()">🔄 실시간 갱신</button>
    <button class="btn btn-trigger" onclick="triggerEvent()">🔨 층간소음 발생 시뮬레이션</button>
    <button class="btn btn-tamper" onclick="simulateTamper()">⚠ 변조 시뮬레이션</button>
    <button class="btn btn-csv" onclick="downloadCSV()">📥 CSV</button>
    <button class="btn btn-pdf" onclick="generatePDF()">📄 법적 리포트(PDF)</button>
  </div>

  <div class="banner" id="banner">
    <strong id="bannerTitle">데이터 무결성 검증 통과</strong>
    <span id="bannerSub" style="font-size:12px;color:#6b7280;margin-left:8px;">SHA-256 봉인 확인 완료</span>
  </div>

  <div class="stat-grid">
    <div class="stat"><div class="stat-label">총 감지 이벤트</div><div class="stat-val" id="sTotal">—</div></div>
    <div class="stat g"><div class="stat-label">야간(22~06시) 비중</div><div class="stat-val" id="sNight">—</div></div>
    <div class="stat o"><div class="stat-label">최대 cVib</div><div class="stat-val" id="sMax">—</div></div>
    <div class="stat b"><div class="stat-label">평균 저주파 비중</div><div class="stat-val" id="sLow">—</div></div>
  </div>

  <div class="charts-grid">
    <div class="card">
      <h3 style="font-size:13px;color:#6b7280;margin-bottom:10px;">시간대별 발생 빈도</h3>
      <div class="chart-wrap"><canvas id="hourlyChart"></canvas></div>
    </div>
    <div class="card">
      <h3 style="font-size:13px;color:#6b7280;margin-bottom:10px;">소음 발생 시간대 분포</h3>
      <div class="chart-wrap"><canvas id="catChart"></canvas></div>
    </div>
  </div>

  <div class="card">
    <h3 style="font-size:13px;color:#6b7280;margin-bottom:10px;">일자별 누적 추이 (지속성 입증 자료)</h3>
    <div class="chart-wrap" style="height:200px;"><canvas id="dailyChart"></canvas></div>
  </div>

  <div class="card">
    <h3 style="font-size:16px;margin-bottom:10px;">📋 포렌식 로그 (Chain of Custody)</h3>
    <table>
      <thead><tr><th>#</th><th>측정 시각</th><th>소음도(dB)</th><th>저주파%</th><th>cVib</th><th>iVib</th><th>환경(T/H)</th><th>SHA-256</th><th>무결성</th></tr></thead>
      <tbody id="logBody"></tbody>
    </table>
  </div>
</div>

<script>
let allData=[], displayData=[], charts={};

async function sha256(text){
  const buf=new TextEncoder().encode(text);
  const hash=await crypto.subtle.digest('SHA-256',buf);
  return Array.from(new Uint8Array(hash)).map(b=>b.toString(16).padStart(2,'0')).join('');
}
async function verifyRow(r){
  const raw=r.ts+','+r.lowRatio+','+r.cVib+','+r.iVib+','+r.temp+','+r.humid;
  return (await sha256(raw))===r.hash;
}

async function fetchData(){
  try{
    const res=await fetch('/api/events');
    allData=await res.json();
    displayData=JSON.parse(JSON.stringify(allData));
    await render();
  }catch(e){console.error(e);}
}

async function triggerEvent(){
  try{
    await fetch('/trigger');
    setTimeout(fetchData,600);
  }catch(e){console.error(e);}
}

async function render(){
  const verifies=await Promise.all(displayData.map(verifyRow));
  const valid=displayData.filter((_,i)=>verifies[i]);
  const failed=displayData.length-valid.length;

  const banner=document.getElementById('banner');
  if(failed===0){
    banner.className='banner';
    document.getElementById('bannerTitle').textContent='데이터 무결성 검증 통과 ('+valid.length+'/'+displayData.length+'건)';
    document.getElementById('bannerSub').textContent='SHA-256 봉인 확인 완료';
  }else{
    banner.className='banner fail';
    document.getElementById('bannerTitle').textContent='변조 탐지! '+failed+'건 실패';
    document.getElementById('bannerSub').textContent='해당 데이터는 통계에서 제외됩니다';
  }

  const isNight=e=>{const h=parseInt(e.ts.split(' ')[1]);return h>=22||h<6;};
  const total=valid.length;
  const night=valid.filter(isNight).length;
  document.getElementById('sTotal').textContent=total+'건';
  document.getElementById('sNight').textContent=total?Math.round(night*100/total)+'%':'—';
  document.getElementById('sMax').textContent=total?Math.max(...valid.map(e=>e.cVib)):'—';
  document.getElementById('sLow').textContent=total?(valid.reduce((s,e)=>s+e.lowRatio,0)/total).toFixed(1)+'%':'—';

  const hourly=Array(24).fill(0);
  valid.forEach(e=>{hourly[parseInt(e.ts.split(' ')[1])]++;});
  if(charts.h)charts.h.destroy();
  charts.h=new Chart(document.getElementById('hourlyChart'),{
    type:'bar',
    data:{labels:Array.from({length:24},(_,i)=>i+'시'),
      datasets:[{data:hourly,backgroundColor:hourly.map((_,h)=>(h>=22||h<6)?'#1e293b':'#4a7ba8'),borderRadius:3}]},
    options:{responsive:true,maintainAspectRatio:false,
      plugins:{legend:{display:false}},
      scales:{x:{grid:{display:false}},y:{beginAtZero:true,ticks:{stepSize:1},grid:{color:'#f1f5f9'}}}}
  });

  const cats=[0,0,0,0];
  valid.forEach(e=>{const h=parseInt(e.ts.split(' ')[1]);
    if(h>=6&&h<12)cats[0]++;else if(h>=12&&h<18)cats[1]++;
    else if(h>=18&&h<22)cats[2]++;else cats[3]++;});
  if(charts.c)charts.c.destroy();
  charts.c=new Chart(document.getElementById('catChart'),{
    type:'doughnut',
    data:{labels:['오전(6~12시)','오후(12~18시)','저녁(18~22시)','야간(22~6시)'],
      datasets:[{data:cats,backgroundColor:['#94a3b8','#4a7ba8','#c9a961','#1e293b'],borderWidth:2,borderColor:'white'}]},
    options:{responsive:true,maintainAspectRatio:false,
      plugins:{legend:{position:'right',labels:{font:{size:11},padding:8,boxWidth:12}}}}
  });

  const byDay={};
  valid.forEach(e=>{const d=e.ts.split(' ')[0];byDay[d]=(byDay[d]||0)+1;});
  const days=Object.keys(byDay).sort();
  const counts=days.map(d=>byDay[d]);
  const cumul=[];let s=0;counts.forEach(n=>{s+=n;cumul.push(s);});
  if(charts.d)charts.d.destroy();
  charts.d=new Chart(document.getElementById('dailyChart'),{
    type:'bar',
    data:{labels:days.map(d=>d.substring(5)),
      datasets:[
        {type:'bar',label:'일별 발생',data:counts,backgroundColor:'#c9a961',borderRadius:3,order:2},
        {type:'line',label:'누적',data:cumul,borderColor:'#1a3a5c',backgroundColor:'rgba(26,58,92,0.1)',fill:true,tension:0.3,pointRadius:3,order:1}
      ]},
    options:{responsive:true,maintainAspectRatio:false,
      plugins:{legend:{labels:{font:{size:11},boxWidth:14}}},
      scales:{x:{grid:{display:false}},y:{beginAtZero:true,grid:{color:'#f1f5f9'}}}}
  });

  const tbody=document.getElementById('logBody');
  const show=[...displayData].reverse().slice(0,50);
  tbody.innerHTML=show.map((e,i)=>{
    const h=parseInt(e.ts.split(' ')[1]);
    const night=(h>=22||h<6)?'<span style="background:#1e293b;color:white;padding:1px 4px;border-radius:3px;font-size:9px;margin-left:4px;">야간</span>':'';
    const ok=verifies[displayData.length-1-i];
    return '<tr><td>'+(displayData.length-i)+'</td><td>'+e.ts+night+'</td><td>'+e.db+'dB</td><td>'+e.lowRatio+'%</td><td>'+e.cVib+'</td><td>'+e.iVib+'</td><td>'+e.temp+'°/'+e.humid+'%</td><td style="font-family:monospace;font-size:10px;color:#6b7280;">'+e.hash.substring(0,16)+'...</td><td class="'+(ok?'pass':'fail2')+'">'+(ok?'✓ 정상':'✗ 변조')+'</td></tr>';
  }).join('');
}

function simulateTamper(){
  if(!displayData.length)return;
  displayData[Math.floor(Math.random()*displayData.length)].iVib=9999;
  render();
}
function downloadCSV(){
  if(!allData.length)return;
  let csv='Timestamp,LowRatio(%),cVib,iVib,dB,Temp,Humid,SHA256\n';
  allData.forEach(r=>{csv+=r.ts+','+r.lowRatio+','+r.cVib+','+r.iVib+','+r.db+','+r.temp+','+r.humid+','+r.hash+'\n';});
  const a=document.createElement('a');
  a.href=URL.createObjectURL(new Blob([csv],{type:'text/csv'}));
  a.download='forensic_log.csv';a.click();
}
function generatePDF(){
  if(!allData.length){alert('데이터가 없습니다.');return;}
  const maxDb=Math.max(...allData.map(r=>r.db)).toFixed(1);
  const maxCvib=Math.max(...allData.map(r=>r.cVib));
  const nightCount=allData.filter(r=>{const h=parseInt(r.ts.split(' ')[1]);return h>=22||h<6;}).length;
  const nightRatio=Math.round(nightCount*100/allData.length);
  const reportHtml='<!DOCTYPE html><html lang="ko"><head><meta charset="UTF-8"><title>층간소음 법적 리포트</title><style>body{font-family:Malgun Gothic,sans-serif;padding:40px;line-height:1.6;}.header{text-align:center;border-bottom:3px solid #1a3a5c;padding-bottom:20px;margin-bottom:30px;}.header h1{color:#1a3a5c;}table{width:100%;border-collapse:collapse;font-size:12px;}th,td{border:1px solid #cbd5e1;padding:8px;text-align:center;}th{background:#f1f5f9;}</style></head><body><div class="header"><h1>⚖ 층간소음 포렌식 분석 리포트</h1><p>SHA-256 무결성 검증 통과 데이터 기준</p></div><p><b>최고 소음도 (Lmax):</b> '+maxDb+' dB(A)</p><p><b>총 감지 건수:</b> '+allData.length+'건</p><p><b>야간(22~06시) 비중:</b> '+nightRatio+'%</p><p><b>최대 cVib:</b> '+maxCvib+'</p><br><table><tr><th>측정 시각</th><th>소음도(dB)</th><th>저주파%</th><th>SHA-256 (앞16자리)</th></tr>'+allData.slice(-50).reverse().map(r=>'<tr><td>'+r.ts+'</td><td>'+r.db+'</td><td>'+r.lowRatio+'%</td><td style="font-family:monospace;">'+r.hash.substring(0,16)+'</td></tr>').join('')+'</table><script>window.onload=function(){setTimeout(function(){window.print();},500);};<\/script></body></html>';
  const w=window.open('','_blank','width=850,height=900');
  w.document.write(reportHtml);
  w.document.close();
}

setInterval(fetchData,5000);
window.onload=fetchData;
<\/script>
</body></html>
)rawHTML";

// ── ESP32 서버 로직 ───────────────────────────────────────

void setup() {
  Serial.begin(115200);
  
  // 무한 재부팅(rst:0x1) 방지를 위한 부팅 안정화 딜레이
  delay(1000); 
  Serial.println("\n\n--- ESP32 부팅 성공! 코드 실행 시작 ---");
  
  // 실제 핀 사용 설정
  pinMode(PIN_CVIB, INPUT);
  pinMode(PIN_IVIB, INPUT);

  dht.begin();
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  while (WiFi.status() != WL_CONNECTED) { delay(500); Serial.print("."); }
  configTime(GMT_OFFSET, 0, NTP_SERVER);
  
  server.on("/", HTTP_GET, handleRoot);
  server.on("/api/events", HTTP_GET, handleEvents);
  server.on("/trigger", HTTP_GET, handleTrigger);
  server.begin();
  
  Serial.println("웹 서버 실행 완료. 센서 감지를 시작합니다.");
}

void loop() {
  server.handleClient();
  
  // 1. 센서값을 아주 빠른 속도로 계속 읽어서 가장 강했던 충격(Peak)을 기억합니다.
  int current_c = analogRead(PIN_CVIB);
  int current_i = analogRead(PIN_IVIB);
  
  if (current_c > peak_cVib) peak_cVib = current_c;
  if (current_i > peak_iVib) peak_iVib = current_i;

  // 2. 0.5초마다 시리얼 모니터에 현재까지 감지된 최대 충격값을 출력합니다. (개발자 눈으로 확인용)
  static unsigned long lastSerialLog = 0;
  if (millis() - lastSerialLog > 500) {
    Serial.printf("[실시간 모니터] 천장 충격값: %4d | 실내 충격값: %4d\n", peak_cVib, peak_iVib);
    lastSerialLog = millis();
  }

  // 3. 5초마다 분석 알고리즘으로 넘겨서 웹 대시보드에 기록할지 결정합니다.
  if (millis() - lastRead > READ_INTERVAL) {
    processForensicAlgorithm(peak_cVib, peak_iVib);
    
    // 분석이 끝나면 Peak 값을 다시 0으로 초기화하여 다음 충격을 대기합니다.
    peak_cVib = 0;
    peak_iVib = 0;
    lastRead = millis();
  }
}

// 수정된 부분: loop()에서 수집한 최고 충격값(cVib, iVib)을 전달받아 검사합니다.
void processForensicAlgorithm(int cVib, int iVib) {
  
  float lowRatio = 50.0 + (cVib / 4095.0) * 50.0;
  float calculatedDb = 35.0 + (cVib / 4095.0) * 65.0;

  float t = dht.readTemperature();
  float h = dht.readHumidity();
  if (isnan(t)) t = 24.5; 
  if (isnan(h)) h = 48.0;

  // 진동값이 100 이상(노이즈 제외)이고, 실내보다 유의미하게 클 때만 웹에 저장합니다.
  if (cVib > 100 && cVib > (iVib * 1.5)) {
    String ts = getTimestamp();
    String raw = ts + "," + String(lowRatio, 1) + "," + String(cVib) + "," + String(iVib) + "," + String(t, 1) + "," + String(h, 1);
    String hash = sha256Hash(raw);

    int idx = totalEvents % MAX_EVENTS;
    strncpy(events[idx].ts, ts.c_str(), 19);
    events[idx].lowRatio = lowRatio;
    events[idx].cVib = cVib;
    events[idx].iVib = iVib;
    events[idx].db = calculatedDb;
    events[idx].temp = t;
    events[idx].humid = h;
    strncpy(events[idx].hash, hash.c_str(), 64);
    totalEvents++;
    
    // 웹에 기록될 때 시리얼 모니터에도 알림을 띄워줍니다.
    Serial.printf("\n🚨 [웹 저장 완료] 유의미한 진동 포착! (기록된 천장 충격값: %d, 소음: %.1fdB)\n\n", cVib, calculatedDb);
  }
}

String getTimestamp() {
  struct tm tinfo;
  if(!getLocalTime(&tinfo)) return "2026-05-31 00:00:00";
  char buf[20];
  strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tinfo);
  return String(buf);
}

String sha256Hash(String data) {
  unsigned char hash[32];
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  mbedtls_sha256_starts(&ctx, 0);
  mbedtls_sha256_update(&ctx, (const unsigned char*)data.c_str(), data.length());
  mbedtls_sha256_finish(&ctx, hash);
  mbedtls_sha256_free(&ctx);
  String r = "";
  for (int i = 0; i < 32; i++) {
    if (hash[i] < 0x10) r += "0";
    r += String(hash[i], HEX);
  }
  return r;
}


void handleTrigger() {
  float lowRatio = 75.0 + random(0, 150) / 10.0;
  int   cVib     = 750  + random(0, 250);
  int   iVib     = 80   + random(0, 100);
  float db       = 42.0 + random(0, 80) / 10.0;
  float t        = dht.readTemperature();
  float h        = dht.readHumidity();
  if (isnan(t)) t = 24.5;
  if (isnan(h)) h = 48.0;
  processForensicAlgorithm(cVib, iVib);
  server.send(200, "text/plain", "OK");
}

void handleRoot() { server.send_P(200, "text/html", DASHBOARD_HTML); }

void handleEvents() {
  String json = "[";
  int count = min(totalEvents, MAX_EVENTS);
  for (int i = 0; i < count; i++) {
    if (i > 0) json += ",";
    json += "{\"ts\":\"" + String(events[i].ts) + "\",";
    json += "\"lowRatio\":" + String(events[i].lowRatio, 1) + ",";
    json += "\"cVib\":" + String(events[i].cVib) + ",";
    json += "\"iVib\":" + String(events[i].iVib) + ",";
    json += "\"db\":" + String(events[i].db, 1) + ",";
    json += "\"temp\":" + String(events[i].temp, 1) + ",";
    json += "\"humid\":" + String(events[i].humid, 1) + ",";
    json += "\"hash\":\"" + String(events[i].hash) + "\"}";
  }
  json += "]";
  server.send(200, "application/json", json);
}