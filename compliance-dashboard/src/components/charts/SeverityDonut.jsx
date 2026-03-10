import React from "react";
import { Doughnut } from "react-chartjs-2";
import {
  Chart as ChartJS,
  ArcElement,
  Tooltip,
  Legend,
} from "chart.js";
import { CHART_COLORS } from "../../utils/helpers";

ChartJS.register(ArcElement, Tooltip, Legend);

export default function SeverityDonut({ stats }) {
  const total = stats.CRITICAL + stats.HIGH + stats.MEDIUM + stats.LOW;

  // Chart.js plugin that draws the number directly in the donut center
  const centerTextPlugin = {
    id: "centerText",
    afterDraw(chart) {
      const { ctx, chartArea } = chart;
      if (!chartArea) return;

      const centerX = (chartArea.left + chartArea.right) / 2;
      const centerY = (chartArea.top + chartArea.bottom) / 2;

      ctx.save();

      // Draw the number
      ctx.font = "800 28px 'Syne', sans-serif";
      ctx.fillStyle = "#e8f4fd";
      ctx.textAlign = "center";
      ctx.textBaseline = "middle";
      ctx.fillText(total, centerX, centerY - 8);

      // Draw "FINDINGS" label below
      ctx.font = "400 10px 'Space Mono', monospace";
      ctx.fillStyle = "#3d5872";
      ctx.letterSpacing = "2px";
      ctx.fillText("FINDINGS", centerX, centerY + 14);

      ctx.restore();
    },
  };

  const data = {
    labels: ["Critical", "High", "Medium", "Low"],
    datasets: [
      {
        data: [stats.CRITICAL, stats.HIGH, stats.MEDIUM, stats.LOW],
        backgroundColor: [
          CHART_COLORS.CRITICAL + "cc",
          CHART_COLORS.HIGH + "cc",
          CHART_COLORS.MEDIUM + "cc",
          CHART_COLORS.LOW + "cc",
        ],
        borderColor: [
          CHART_COLORS.CRITICAL,
          CHART_COLORS.HIGH,
          CHART_COLORS.MEDIUM,
          CHART_COLORS.LOW,
        ],
        borderWidth: 1.5,
        hoverBorderWidth: 2,
      },
    ],
  };

  const options = {
    responsive: true,
    maintainAspectRatio: false,
    cutout: "68%",
    plugins: {
      legend: {
        position: "right",
        labels: {
          color: "#7a9ab8",
          font: { family: "'Space Mono', monospace", size: 11 },
          padding: 16,
          usePointStyle: true,
          pointStyleWidth: 8,
        },
      },
      tooltip: {
        backgroundColor: "#111820",
        borderColor: "#1e2d3d",
        borderWidth: 1,
        titleColor: "#e8f4fd",
        bodyColor: "#7a9ab8",
        titleFont: { family: "'Syne', sans-serif", weight: "700" },
        callbacks: {
          label: (ctx) => {
            const total = ctx.dataset.data.reduce((a, b) => a + b, 0);
            const pct = total ? ((ctx.parsed / total) * 100).toFixed(1) : 0;
            return ` ${ctx.parsed} findings (${pct}%)`;
          },
        },
      },
    },
  };

  return (
    <div className="card" style={{ height: "280px", position: "relative" }}>
      <div className="card-header">
        <span className="card-title">Severity Distribution</span>
        <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-muted)" }}>
          {total} total
        </span>
      </div>
      <div style={{ height: "calc(100% - 48px)", position: "relative" }}>
        {total === 0 ? (
          <div className="empty-state" style={{ padding: "30px" }}>
            <div className="empty-state-icon">◎</div>
            <div className="empty-state-title">No findings</div>
          </div>
        ) : (
          <Doughnut
            data={data}
            options={options}
            plugins={[centerTextPlugin]}
          />
        )}
      </div>
    </div>
  );
}