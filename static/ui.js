const btn = document.getElementById('toggleSidebar');
const sidebar = document.getElementById('sidebar');
if(btn && sidebar){
  btn.addEventListener('click', ()=> sidebar.classList.toggle('open'));
}
document.addEventListener('click', async (e)=>{
  const b = e.target.closest('[data-copy-btn]');
  if(!b) return;
  const host = b.closest('.copywrap'); if(!host) return;
  const tgt = host.querySelector('[data-copy]'); if(!tgt) return;
  const text = tgt.innerText;
  try{
    await navigator.clipboard.writeText(text);
    b.classList.add('ok'); const old=b.textContent; b.textContent='Copied';
    setTimeout(()=>{b.textContent=old;b.classList.remove('ok')},1200);
  }catch{ const old=b.textContent; b.textContent='Copy failed'; setTimeout(()=>b.textContent=old,1200); }
});
