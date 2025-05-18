import argparse
from tkinter import *
import tkinter.font
import json
import _thread
import time
from router import Router
from network import Network
from packet import Packet


class App:
    """Tkinter GUI application for network simulation visualizations."""

    def __init__(self, root, network, network_params):
        self.network = network
        self.network_params = network_params
        Packet.animate = self.packet_send
        Network.visualize_changes_callback = self.visualize_changes
        self.animate_rate = network_params["visualize"]["animate_rate"]
        self.latency_correction = network_params["visualize"]["latency_correction"]
        self.client_following = None
        self.router_following = None
        self.display_current_routes_rate = 100
        self.display_current_debug_rate = 50

        # Enclosing frame
        self.frame = Frame(root)
        self.frame.grid(padx=10, pady=10)

        # Canvas for drawing the network
        self.canvas_width = network_params["visualize"]["canvas_width"]
        self.canvas_height = network_params["visualize"]["canvas_height"]
        self.canvas = Canvas(
            self.frame, width=self.canvas_width, height=self.canvas_height
        )
        self.canvas.grid(column=1, row=1, rowspan=4)

        # Text for displaying current routes
        self.route_label = Label(self.frame, text="Current routes:")
        self.route_label.grid(column=3, row=1)
        self.route_scrollbar = Scrollbar(self.frame)
        self.route_scrollbar.grid(column=2, row=2, sticky=NE + SE)
        self.route_text = Text(self.frame, yscrollcommand=self.route_scrollbar.set)
        self.route_text.grid(column=3, row=2)

        # Text for displaying debugging information
        self.debug_label = Label(
            self.frame, text="Click on routers to print debug string below:"
        )
        self.debug_label.grid(column=3, row=3)
        self.debug_scrollbar = Scrollbar(self.frame)
        self.debug_scrollbar.grid(column=2, row=4, sticky=NE + SE)
        self.debug_text = Text(self.frame, yscrollcommand=self.debug_scrollbar.set)
        self.debug_text.grid(column=3, row=4)

        self.rect_centers = self.calc_rect_centers()
        self.lines, self.line_labels = self.draw_lines()
        self.rects = self.draw_rectangles()

        _thread.start_new_thread(self.network.run, ())
        _thread.start_new_thread(self.display_current_routes, ())
        _thread.start_new_thread(self.display_current_debug, ())

    def calc_rect_centers(self):
        """Compute the centers of the rectangles representing clients/routers."""
        rect_centers = {}
        grid_size = int(self.network_params["visualize"]["grid_size"])
        self.box_width = self.canvas_width / grid_size
        self.box_height = self.canvas_height / grid_size
        for label in self.network_params["visualize"]["locations"]:
            gx, gy = self.network_params["visualize"]["locations"][label]
            rect_centers[label] = (
                gx * self.box_width + self.box_width / 2,
                gy * self.box_height + self.box_height / 2,
            )
        return rect_centers

    def draw_lines(self):
        """Draw lines corresponding to links."""
        lines = {}
        line_labels = {}
        for addr1, addr2, _, _, c12, c21 in self.network_params["links"]:
            line, line_label = self.draw_line(addr1, addr2, c12, c21)
            lines[(addr1, addr2)] = line
            line_labels[(addr1, addr2)] = line_label
        return lines, line_labels

    def draw_line(self, addr1, addr2, c12, c21):
        """Draw a single line corresponding to one link."""
        center1, center2 = self.rect_centers[addr1], self.rect_centers[addr2]
        line = self.canvas.create_line(
            center1[0],
            center1[1],
            center2[0],
            center2[1],
            width=self.network_params["visualize"]["line_width"],
            fill=self.network_params["visualize"]["line_color"],
        )
        self.canvas.tag_lower(line)
        tx, ty = (center1[0] + center2[0]) / 2, (center1[1] + center2[1]) / 2

        t = (
            str(c12)
            if c12 == c21
            else f"{addr1}->{addr2}:{c12}, {addr2}->{addr1}:{c21}"
        )
        label = self.canvas.create_text(
            tx,
            ty,
            text=t,
            state=NORMAL,
            font=tkinter.font.Font(
                size=self.network_params["visualize"]["line_font_size"]
            ),
        )
        return line, label

    def draw_rectangles(self):
        """Draw rectangles corresponding to clients/routers."""
        rects = {}
        for label in self.rect_centers:
            if label in self.network.clients:
                fill = self.network_params["visualize"]["client_color"]
            elif label in self.network.routers:
                fill = self.network_params["visualize"]["router_color"]
            c = self.rect_centers[label]
            rect = self.canvas.create_rectangle(
                c[0] - self.box_width / 6,
                c[1] - self.box_height / 6,
                c[0] + self.box_width / 6,
                c[1] + self.box_height / 6,
                fill=fill,
                activeoutline="green",
                activewidth=5,
            )
            self.canvas.tag_bind(
                rect,
                "<1>",
                lambda event, label=label: self.inspect_client_or_router(label),
            )
            rects[label] = rect
            self.canvas.create_text(
                c[0], c[1], text=label, font=tkinter.font.Font(size=18, weight="bold")
            )
        return rects

    def inspect_client_or_router(self, addr):
        """Handle a mouse click on a client or router."""
        if addr in self.network.clients:
            if self.client_following:
                self.canvas.itemconfig(self.rects[self.client_following], width=1)
            if self.client_following != addr:
                self.client_following = addr
                self.canvas.itemconfig(self.rects[addr], width=7)
            else:
                self.client_following = None
        elif addr in self.network.routers:
            if self.router_following:
                self.canvas.itemconfig(
                    self.rects[self.router_following], outline="black", width=1
                )
            if self.router_following != addr:
                self.router_following = addr
                self.canvas.itemconfig(self.rects[addr], width=7)
            else:
                self.router_following = None

    def packet_send(self, packet, src, dst, latency):
        """Callback function to tell the visualization that a packet is being sent."""
        if self.client_following:
            if packet.dst_addr == self.client_following and packet.is_traceroute:
                fill_color = "green"
            else:
                return
        else:
            fill_color = "gray" if packet.is_traceroute else "turquoise"
        latency = latency / self.latency_correction
        cx, cy = self.rect_centers[src]
        dx, dy = self.rect_centers[dst]
        packet_rect = self.canvas.create_rectangle(
            cx - 6, cy - 6, cx + 6, cy + 6, fill=fill_color
        )
        distx, disty = dx - cx, dy - cy
        velocityx, velocityy = (distx * self.animate_rate) / latency, (
            disty * self.animate_rate / latency
        )
        num_steps, step_time = latency / self.animate_rate, self.animate_rate / 1000
        _thread.start_new_thread(
            self.movePacket, (packet_rect, velocityx, velocityy, num_steps, step_time)
        )

    def movePacket(self, packet_rect, vx, vy, num_steps, step_time):
        """Animate a moving packet, running on a separate thread."""
        s = num_steps
        while s > 0:
            time.sleep(step_time)
            self.canvas.move(packet_rect, vx, vy)
            s -= 1
        self.canvas.delete(packet_rect)

    def display_current_routes(self):
        """Display the current routes found by traceroute packets."""
        while True:
            route_string = self.network.get_route_string(label_incorrect=False)
            pos = self.route_scrollbar.get()
            self.route_text.delete(1.0, END)
            self.route_text.insert(1.0, route_string)
            self.route_text.yview_moveto(pos[0])
            time.sleep(self.display_current_routes_rate / 1000)

    def display_current_debug(self):
        """Display the debug string of the currently selected router."""
        while True:
            if self.router_following:
                debug_text = repr(self.network.routers[self.router_following])
                pos = self.debug_scrollbar.get()
                self.debug_text.delete(1.0, END)
                self.debug_text.insert(END, debug_text + "\n")
                self.debug_text.yview_moveto(pos[0])
            time.sleep(self.display_current_debug_rate / 1000)

    def visualize_changes(self, change, target):
        """Make color and text changes to links upon add/remove/cost changes."""
        if change == "up":
            addr1, addr2, _, _, c12, c21 = target
            new_line, _ = self.draw_line(addr1, addr2, c12, c21)
            self.lines[(addr1, addr2)] = new_line
        elif change == "down":
            addr1, addr2 = target
            self.canvas.delete(self.lines[(addr1, addr2)])
            self.canvas.delete(self.line_labels[(addr1, addr2)])


def main():
    parser = argparse.ArgumentParser(description="Visualize a network simulation.")
    parser.add_argument(
        "net_json_path",
        type=str,
        help="Path to the network simulation configuration file (JSON).",
    )
    parser.add_argument(
        "router",
        type=str,
        choices=["DV", "LS"],
        nargs="?",
        default=None,
        help="DV for DVrouter and LS for LSrouter. If not provided, Router is used.",
    )
    args = parser.parse_args()

    with open(args.net_json_path, "r") as f:
        visualize_params = json.load(f)

    RouterClass = Router
    if args.router == "DV":
        from DVrouter import DVrouter

        RouterClass = DVrouter
    elif args.router == "LS":
        from LSrouter import LSrouter

        RouterClass = LSrouter

    net = Network(args.net_json_path, RouterClass, visualize=True)
    root = Tk()
    root.wm_title("Network Visualization")
    App(root, net, visualize_params)
    root.mainloop()


if __name__ == "__main__":
    main()
