async function loadPrediction(){

    const predict=await fetch("http://127.0.0.1:8000/predict");
    const drift=await fetch("http://127.0.0.1:8000/drift");
    const shap=await fetch("http://127.0.0.1:8000/shap");
    const system=await fetch("http://127.0.0.1:8000/system");

    const p=await predict.json();
    const d=await drift.json();
    const s=await shap.json();
    const sys=await system.json();

    document.getElementById("flow").innerText=p.flow_id;
    document.getElementById("prob").innerText=p.xgb_probability.toFixed(5);

    document.getElementById("xgb").innerText=
        p.xgb_prediction==1?"Attack":"Benign";

    document.getElementById("iso").innerText=
        p.isolation_prediction==1?"Attack":"Normal";

    document.getElementById("hybrid").innerText=
        p.hybrid_prediction==1?"ATTACK":"BENIGN";

    document.getElementById("hybrid").className=
        p.hybrid_prediction==1?"red":"green";

    document.getElementById("drift").innerText=
        d.drift_detected?"Drift Detected":"No Drift";

    document.getElementById("system").innerText=sys.status;

    const list=document.getElementById("shap");
    list.innerHTML="";

    if(s.top_features){
        s.top_features.forEach(f=>{

            const li=document.createElement("li");
            li.innerText=f.feature+" : "+f.value;
            list.appendChild(li);

        });
    }

}

loadPrediction();

setInterval(loadPrediction,2000);