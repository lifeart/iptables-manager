/**
 * Sparkline mini-chart — 16px tall, 80px wide, canvas-based.
 *
 * Renders a tiny area chart of recent data points (e.g., last 5 minutes).
 */

export class Sparkline {
  private canvas: HTMLCanvasElement;
  private ctx: CanvasRenderingContext2D;
  private data: number[] = [];
  private maxPoints = 30;
  private color: string;

  constructor(container: HTMLElement, color = '#34C759') {
    // Resolve CSS variable fallback: extract hex from "var(--name, #hex)"
    const varMatch = color.match(/var\([^,]+,\s*(#[0-9A-Fa-f]{3,8})\)/);
    this.color = varMatch ? varMatch[1] : color;
    this.canvas = document.createElement('canvas');
    this.canvas.width = 80;
    this.canvas.height = 16;
    this.canvas.className = 'sparkline-canvas';
    this.canvas.setAttribute('aria-hidden', 'true');

    const ctx = this.canvas.getContext('2d');
    if (!ctx) throw new Error('Canvas 2D context not available');
    this.ctx = ctx;

    container.appendChild(this.canvas);
  }

  /**
   * Add a data point and redraw.
   */
  addPoint(value: number): void {
    this.data.push(value);
    if (this.data.length > this.maxPoints) {
      this.data.shift();
    }
    this.draw();
  }

  /**
   * Set all data points and redraw.
   */
  setData(points: number[]): void {
    this.data = points.slice(-this.maxPoints);
    this.draw();
  }

  /**
   * Update the line/fill color.
   */
  setColor(color: string): void {
    this.color = color;
    this.draw();
  }

  /**
   * Remove the canvas from DOM.
   */
  destroy(): void {
    this.canvas.remove();
  }

  private draw(): void {
    const { ctx, canvas, data, color } = this;
    const w = canvas.width;
    const h = canvas.height;

    ctx.clearRect(0, 0, w, h);

    if (data.length < 2) return;

    const max = Math.max(...data, 1);
    const step = w / (data.length - 1);

    // Draw area fill
    ctx.beginPath();
    ctx.moveTo(0, h);

    for (let i = 0; i < data.length; i++) {
      const x = i * step;
      const y = h - (data[i] / max) * (h - 2);
      if (i === 0) {
        ctx.lineTo(x, y);
      } else {
        ctx.lineTo(x, y);
      }
    }

    ctx.lineTo((data.length - 1) * step, h);
    ctx.closePath();

    // Parse color for fill opacity
    ctx.fillStyle = color + '33'; // ~20% opacity
    ctx.fill();

    // Draw line
    ctx.beginPath();
    for (let i = 0; i < data.length; i++) {
      const x = i * step;
      const y = h - (data[i] / max) * (h - 2);
      if (i === 0) {
        ctx.moveTo(x, y);
      } else {
        ctx.lineTo(x, y);
      }
    }

    ctx.strokeStyle = color;
    ctx.lineWidth = 1.5;
    ctx.lineJoin = 'round';
    ctx.lineCap = 'round';
    ctx.stroke();
  }
}
