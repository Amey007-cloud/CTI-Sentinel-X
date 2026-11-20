const $=id=>document.getElementById(id);
const esc=CTI.escape;
let sessionId=localStorage.getItem('cti_sentinel_session')||((crypto.randomUUID&&crypto.randomUUID())||('session-'+Date.now()));
localStorage.setItem('cti_sentinel_session',sessionId);
let isSending=false;
function safeMarkdown(value){
  let text=esc(value||'');
  text=text.replace(/^### (.+)$/gm,'<h4>$1</h4>').replace(/^## (.+)$/gm,'<h3>$1</h3>').replace(/^# (.+)$/gm,'<h3>$1</h3>');
  text=text.replace(/\*\*(.+?)\*\*/g,'<strong>$1</strong>').replace(/`([^`]+)`/g,'<code>$1</code>');
  text=text.replace(/\n\n/g,'</p><p>').replace(/\n/g,'<br>');
  return `<p>${text}</p>`;
}
function addMessage(role,content,sources=[],meta={}){
  const area=$('chat-messages');
  const welcome=area.querySelector('.welcome-state'); if(welcome)welcome.remove();
  const row=document.createElement('div'); row.className=`message-row ${role==='user'?'user-row':'assistant-row'}`;
  const avatar=role==='user'?'AK':'✳';
  row.innerHTML=`<div class="message-avatar ${role}">${avatar}</div><div class="message-content"><div class="message-meta"><b>${role==='user'?'YOU':'SENTINEL AI ANALYST'}</b><span>${new Date().toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'})}</span>${role==='assistant'&&meta.provider?`<span class="provider-chip">${esc(meta.provider)}</span>`:''}</div><div class="message-bubble">${safeMarkdown(content)}</div>${sources.length?`<details class="message-sources" open><summary>◈ ${sources.length} retrieved source${sources.length===1?'':'s'}</summary><div>${sources.map(s=>`<article><b>${esc(s.source)}</b><small>${esc(s.platform||'ALL')} · ${esc(s.record_type||'knowledge')} · relevance ${Number(s.score||0).toFixed(3)} ${s.is_demo?'· SYNTHETIC DEMO':''}</small><p>${esc(s.excerpt||'')}</p>${s.source_url?`<a href="${esc(s.source_url)}" target="_blank" rel="noopener">Open source ↗</a>`:''}</article>`).join('')}</div></details>`:''}<div class="message-actions"><button class="copy-message">Copy response</button></div></div>`;
  area.appendChild(row); row.querySelector('.copy-message')?.addEventListener('click',()=>navigator.clipboard.writeText(content).then(()=>CTI.toast('Response copied.','success')).catch(()=>CTI.toast('Clipboard unavailable.','error')));
  area.scrollTop=area.scrollHeight;
  if(sources.length)renderSources(sources);
}
function renderSources(sources){
  $('source-trail').innerHTML=sources.map((s,i)=>`<div class="source-trail-item"><div class="source-num">0${i+1}</div><div><b>${esc(s.source)}</b><small>${esc(s.platform||'ALL')} · ${esc(s.record_type||'knowledge')} · ${Number(s.score||0).toFixed(3)} relevance ${s.is_demo?'· SYNTHETIC DEMO':''}</small><p>${esc(s.excerpt||'')}</p>${s.source_url?`<a href="${esc(s.source_url)}" target="_blank" rel="noopener">Source ↗</a>`:''}</div></div>`).join('')||'<div class="empty-state">No source evidence matched this question.</div>';
}
function typing(){const area=$('chat-messages');const row=document.createElement('div');row.className='message-row assistant-row typing-row';row.id='typing';row.innerHTML='<div class="message-avatar assistant">✳</div><div class="message-content"><div class="message-meta"><b>SENTINEL IS THINKING</b></div><div class="typing-bubble"><i></i><i></i><i></i></div></div>';area.appendChild(row);area.scrollTop=area.scrollHeight;}
async function loadHistory(){
  try{const data=await CTI.fetchJSON('/api/assistant/sessions/'+encodeURIComponent(sessionId));
    if(data.messages?.length){$('chat-messages').innerHTML='';data.messages.forEach(m=>{if(m.role==='user')addMessage('user',m.content);else addMessage('assistant',m.content,m.sources||[],{provider:m.provider})});}
  }catch(e){/* backend health panel provides the visible connection state */}
}
async function sendMessage(value){
  if(isSending||!value.trim())return; isSending=true; const message=value.trim(); $('chat-input').value=''; $('send-chat').disabled=true;
  addMessage('user',message); typing();
  try{
    const response=await CTI.fetchJSON('/api/assistant/chat',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({session_id:sessionId,message,platform:$('chat-platform').value,top_k:Number($('chat-topk').value)})});
    $('typing')?.remove(); addMessage('assistant',response.response,response.sources||[],{provider:response.provider});
    $('retrieval-mode').textContent=String(response.retrieval_mode||'RAG').replaceAll('-',' ').toUpperCase();
    $('assistant-subtitle').textContent=`${response.provider} · embeddings ${response.embedding_provider||'configured'} · ${response.latency_ms} ms · ${response.sources?.length||0} cited sources`;
    loadMetrics();
  }catch(error){$('typing')?.remove();addMessage('assistant',`The assistant service returned an error: ${error.message}\n\nCheck the AI fabric health and confirm MongoDB is running.`);CTI.toast(error.message,'error')}
  finally{isSending=false;$('send-chat').disabled=false;$('chat-input').focus()}
}
$('chat-form').addEventListener('submit',e=>{e.preventDefault();sendMessage($('chat-input').value)});
$('chat-input').addEventListener('keydown',e=>{if(e.key==='Enter'&&!e.shiftKey){e.preventDefault();$('chat-form').requestSubmit()} });
document.querySelectorAll('.prompt-suggestion').forEach(b=>b.addEventListener('click',()=>sendMessage(b.dataset.prompt)));
$('new-chat').addEventListener('click',()=>{sessionId=(crypto.randomUUID&&crypto.randomUUID())||('session-'+Date.now());localStorage.setItem('cti_sentinel_session',sessionId);$('chat-messages').innerHTML=`<div class="welcome-state"><div class="welcome-orb">✳</div><span class="panel-kicker">NEW ANALYST SESSION</span><h2>Ready for the next signal.</h2><p>Your next conversation will be stored as a separate MongoDB session.</p></div>`;$('source-trail').innerHTML='<div class="empty-state">Sources will appear after your first question.</div>';});
async function loadHealth(){try{const h=await CTI.fetchJSON('/api/assistant/health');const p=h.providers||{};$('ai-status').innerHTML='<i></i> ASSISTANT API ONLINE';$('ai-status').classList.add('online');$('service-health').innerHTML=`<div class="health-row"><span>MongoDB operational store</span><b class="health-ok">CONNECTED</b></div><div class="health-row"><span>LLM provider (selected)</span><b class="health-warn">${esc(p.llm_provider||'unknown')} · availability checked per request</b></div><div class="health-row"><span>Embedding provider (selected)</span><b class="health-warn">${esc(p.embedding_provider||'unknown')} · fallback disclosed</b></div><div class="health-row"><span>Vector retrieval</span><b class="health-ok">${esc(p.vector_mode||'local')}</b></div>`;$('kb-doc-count').textContent=h.knowledge_documents??0;$('kb-chunk-count').textContent=h.knowledge_chunks??0;}catch(e){$('ai-status').textContent='AI BACKEND UNREACHABLE';$('ai-status').classList.add('offline');$('service-health').innerHTML=`<div class="notice error">${esc(e.message)}</div>`}}
async function loadMetrics(){try{const m=await CTI.fetchJSON('/api/assistant/metrics');$('kb-doc-count').textContent=m.knowledge_documents??0;$('kb-chunk-count').textContent=m.knowledge_chunks??0;$('chat-latency').textContent=m.avg_latency_ms?`${m.avg_latency_ms} ms`:'—';$('chat-sessions').textContent=m.sessions??0;}catch(e){}}
const query=new URLSearchParams(location.search);if(query.get('platform'))$('chat-platform').value=query.get('platform').toUpperCase();if(query.get('q'))$('chat-input').value=query.get('q');
loadHealth();loadMetrics();loadHistory();
