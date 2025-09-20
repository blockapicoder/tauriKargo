const canvas = document.getElementById('gfx') as HTMLCanvasElement;
if (!('gpu' in navigator)) {
    throw new Error('WebGPU non disponible dans ce navigateur');
}

const context = canvas.getContext('webgpu') as unknown as GPUCanvasContext;
(async () => {
    const adapter = await navigator.gpu.requestAdapter();
    if (!adapter) throw new Error('Aucun adapter GPU disponible');

    const device = await adapter.requestDevice();
    const format = navigator.gpu.getPreferredCanvasFormat();

    function resizeCanvas() {
        const dpr = window.devicePixelRatio || 1;
        const w = Math.floor(canvas.clientWidth * dpr);
        const h = Math.floor(canvas.clientHeight * dpr);
        if (canvas.width !== w || canvas.height !== h) {
            canvas.width = w;
            canvas.height = h;
        }
    }
    resizeCanvas();
    addEventListener('resize', () => {
        resizeCanvas();
        context.configure({ device, format, alphaMode: 'opaque' });
    });

    context.configure({ device, format, alphaMode: 'opaque' });

    const shaderCode = /* wgsl */`
@vertex
fn vs_main(@builtin(vertex_index) VertexIndex : u32)
  -> @builtin(position) vec4f {
  var pos = array<vec2f, 3>(
    vec2f(0.0,  0.6),
    vec2f(-0.6, -0.6),
    vec2f(0.6, -0.6)
  );
  return vec4f(pos[VertexIndex], 0.0, 1.0);
}

@fragment
fn fs_main() -> @location(0) vec4f {
  return vec4f(0.2, 0.8, 1.0, 1.0); // cyan
}
`;

    const shaderModule = device.createShaderModule({ code: shaderCode });

    const pipeline = device.createRenderPipeline({
        layout: 'auto',
        vertex: { module: shaderModule, entryPoint: 'vs_main' },
        fragment: { module: shaderModule, entryPoint: 'fs_main', targets: [{ format }] },
        primitive: { topology: 'triangle-list' },
    });

    function frame() {
        const encoder = device.createCommandEncoder();
        const pass = encoder.beginRenderPass({
            colorAttachments: [{
                view: context.getCurrentTexture().createView(),
                clearValue: { r: 0.05, g: 0.06, b: 0.09, a: 1.0 },
                loadOp: 'clear',
                storeOp: 'store',
            }],
        });
        pass.setPipeline(pipeline);
        pass.draw(3, 1, 0, 0);
        pass.end();
        device.queue.submit([encoder.finish()]);
        requestAnimationFrame(frame);
    }
    frame();
})().then(() => {

})