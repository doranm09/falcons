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
          updateScanHistory();
          nodesBody.innerHTML = '';
          statusData.nodes.forEach(node => {
            nodesBody.innerHTML += `
              <tr>
                <td>${node.ip_address}</td>
                <td>${node.name}</td>
                <td>${node.status}</td>
                <td>${node.last_heartbeat || ''}</td>
                <td>
                  ${node.description || ''}
                  <ul style="font-size: 0.85em; margin-top: 0.5em;">
                    ${(node.interfaces || []).map(i => `<li>${i.name}: ${i.ip} / ${i.mac}</li>`).join('')}
                  </ul>
                </td>
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
                  'text-valign': 'bottom',         // Keeps label below the node
                  'text-halign': 'center',         // Center-align the label horizontally
                  'color': '#000',
                  'font-size': 12,
                  'text-margin-y': 6,              // Adds space below the node
                  'text-background-color': '#fff', // Improves readability
                  'text-background-opacity': 1,
                  'text-background-shape': 'roundrectangle',
                  'text-border-color': '#333',
                  'text-border-width': 0.5,
                  'text-border-opacity': 0.8
                }
              },
              {
                selector: 'edge',
                style: {
                  'label': 'data(weight)',
                  'font-size': 10,
                  'color': '#000',
                  'text-background-color': '#fff',
                  'text-background-opacity': 1,
                  'text-background-shape': 'roundrectangle',
                  'text-rotation': 'autorotate',
                  'curve-style': 'bezier',
                  'width': 2,

                  // color mapped to numeric value
                  'line-color': 'mapData(raw_weight, 0, 6, green, red)',
                  'target-arrow-shape': 'triangle',
                  'target-arrow-color': 'mapData(raw_weight, 0, 6, green, red)'
                }
              }
            ],
            layout: {
              name: 'concentric',
              concentric: node => node.degree(),
              levelWidth: () => 2,
              spacingFactor: 5,
              animate: true
            }
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

    function updateScanHistory() {
      fetch('/scan/history/')
        .then(response => response.json())
        .then(data => {
          const historyTable = document.getElementById('scan-history-body');
          historyTable.innerHTML = '';
          data.history.forEach(run => {
            historyTable.innerHTML += `
              <tr>
                <td>${run.timestamp}</td>
                <td>${run.cidr}</td>
                <td>${run.status}</td>
                <td>${run.summary}</td>
              </tr>`;
          });
        });
    }

  });
