// static/dashboard/js/scan.js

document.addEventListener('DOMContentLoaded', function () {
    const scanForm = document.getElementById('scan-form');
    const scanStatus = document.getElementById('scan-status');
    const nodesBody = document.getElementById('nodes-body');
  
    scanForm.addEventListener('submit', async function (e) {
      e.preventDefault();
      const formData = new FormData(scanForm);
      const csrfToken = document.querySelector('[name=csrfmiddlewaretoken]').value;
      const response = await fetch('/scan/start/', {
        method: 'POST',
        headers: { 'X-CSRFToken': csrfToken },
        body: formData
      });
      const data = await response.json();
      const taskId = data.task_id;
      scanStatus.innerText = 'Scan started...';
  
      const interval = setInterval(async () => {
        const statusRes = await fetch(`/scan/status/${taskId}/`);
        const statusData = await statusRes.json();
        if (statusData.state === 'SUCCESS') {
          clearInterval(interval);
          scanStatus.innerText = 'Scan complete. Nodes updated.';
          nodesBody.innerHTML = '';
          statusData.nodes.forEach(node => {
            nodesBody.innerHTML += `
              <tr>
                <td>${node.ip_address}</td>
                <td>${node.name}</td>
                <td>${node.status}</td>
                <td>${node.last_heartbeat || ''}</td>
                <td>${node.description || ''}</td>
              </tr>`;
          });
          renderGraph();
        } else {
          scanStatus.innerText = `Scanning... (${statusData.state})`;
        }
      }, 2000);
    });
  
    window.renderGraph = function () {
      fetch('/graph/data/')
        .then(response => response.json())
        .then(data => {
          const cy = cytoscape({
            container: document.getElementById('cy'),
            elements: data,
            style: [
              {
                selector: 'node',
                style: {
                  'label': 'data(label)',
                  'background-color': '#007bff',
                  'text-valign': 'center',
                  'text-halign': 'center',
                  'color': '#fff',
                  'font-size': 12
                }
              },
              {
                selector: 'edge',
                style: {
                  'label': 'data(weight)',
                  'font-size': 10,
                  'text-background-color': '#ffffff',
                  'text-background-opacity': 1,
                  'text-background-shape': 'roundrectangle',
                  'text-border-color': '#ccc',
                  'text-border-width': 1,
                  'text-border-opacity': 1,
                  'text-rotation': 'autorotate',
                  'line-color': '#999',
                  'target-arrow-shape': 'triangle',
                  'target-arrow-color': '#999',
                  'curve-style': 'bezier',
                  'width': 2
                }
              }
            ],
            
            
            layout: { name: 'cose', animate: true }
          });
  
          let selectedNode = null;
          cy.on('tap', 'node', function (evt) {
            const tapped = evt.target;
            if (!selectedNode) {
              selectedNode = tapped;
              tapped.style('background-color', '#ffc107');
            } else {
              const sourceId = selectedNode.id();
              const targetId = tapped.id();
              fetch(`/shortest-paths/${sourceId}/`)
                .then(res => res.json())
                .then(pathData => {
                  const cost = pathData[targetId];
                  document.getElementById('path-result').innerText =
                    `Shortest path from ${selectedNode.data('label')} to ${tapped.data('label')}: ${cost}`;
                });
              selectedNode.style('background-color', '#007bff');
              selectedNode = null;
            }
          });
        });
    };
  
    renderGraph();
  });
  