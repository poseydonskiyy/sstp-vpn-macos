import AppKit
import CoreGraphics
import Foundation

let destination = URL(fileURLWithPath: CommandLine.arguments[1])
let representations = [(16, 1, "icp4"), (16, 2, "ic11"), (32, 1, "icp5"), (32, 2, "ic12"),
                       (128, 1, "ic07"), (128, 2, "ic13"), (256, 1, "ic08"), (256, 2, "ic14"),
                       (512, 1, "ic09"), (512, 2, "ic10")]

func iconBlock(_ type: String, _ contents: Data) -> Data {
    var bigEndianLength = UInt32(contents.count + 8).bigEndian
    var block = Data(type.utf8)
    withUnsafeBytes(of: &bigEndianLength) { block.append(contentsOf: $0) }
    block.append(contents)
    return block
}

let srgb = CGColorSpace(name: CGColorSpace.sRGB)!
func color(_ r: CGFloat, _ g: CGFloat, _ b: CGFloat, _ a: CGFloat = 1) -> CGColor {
    CGColor(colorSpace: srgb, components: [r, g, b, a])!
}

var representationsData = Data()
for (points, scale, type) in representations {
    let pixels = points * scale
    let context = CGContext(data: nil, width: pixels, height: pixels,
                            bitsPerComponent: 8, bytesPerRow: 0,
                            space: srgb, bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
    let unit = CGFloat(pixels) / 1024
    context.scaleBy(x: unit, y: unit)
    let plate = CGPath(roundedRect: CGRect(x: 86, y: 95, width: 852, height: 852),
                       cornerWidth: 195, cornerHeight: 195, transform: nil)

    context.saveGState()
    context.setShadow(offset: CGSize(width: 0, height: -22 * unit),
                      blur: 36 * unit, color: color(0.02, 0.11, 0.16, 0.52))
    context.addPath(plate)
    context.setFillColor(color(0.045, 0.25, 0.32))
    context.fillPath()
    context.restoreGState()

    context.saveGState()
    context.addPath(plate)
    context.clip()
    let gradient = CGGradient(colorsSpace: srgb,
                              colors: [color(0.08, 0.38, 0.47), color(0.035, 0.12, 0.24)] as CFArray,
                              locations: [0, 1])!
    context.drawLinearGradient(gradient, start: CGPoint(x: 168, y: 947),
                               end: CGPoint(x: 840, y: 112), options: [])
    context.addPath(plate)
    context.setStrokeColor(color(0.64, 0.96, 0.98, 0.28))
    context.setLineWidth(8)
    context.strokePath()
    context.restoreGState()

    let shield = CGMutablePath()
    shield.move(to: CGPoint(x: 512, y: 751))
    shield.addCurve(to: CGPoint(x: 735, y: 681), control1: CGPoint(x: 576, y: 704), control2: CGPoint(x: 648, y: 683))
    shield.addLine(to: CGPoint(x: 735, y: 520))
    shield.addCurve(to: CGPoint(x: 512, y: 282), control1: CGPoint(x: 735, y: 402), control2: CGPoint(x: 646, y: 321))
    shield.addCurve(to: CGPoint(x: 289, y: 520), control1: CGPoint(x: 378, y: 321), control2: CGPoint(x: 289, y: 402))
    shield.addLine(to: CGPoint(x: 289, y: 681))
    shield.addCurve(to: CGPoint(x: 512, y: 751), control1: CGPoint(x: 376, y: 683), control2: CGPoint(x: 448, y: 704))
    shield.closeSubpath()
    context.addPath(shield)
    context.setLineJoin(.round)
    context.setFillColor(color(0.035, 0.24, 0.32, 0.5))
    context.setStrokeColor(color(0.78, 0.99, 1))
    context.setLineWidth(29)
    context.drawPath(using: .fillStroke)

    context.setLineCap(.round)
    context.setLineWidth(27)
    context.setStrokeColor(color(0.35, 0.92, 0.87))
    context.move(to: CGPoint(x: 422, y: 465))
    context.addCurve(to: CGPoint(x: 602, y: 566),
                     control1: CGPoint(x: 512, y: 465), control2: CGPoint(x: 512, y: 566))
    context.strokePath()
    context.setFillColor(color(0.61, 1, 0.92))
    for point in [CGPoint(x: 419, y: 465), CGPoint(x: 605, y: 566)] {
        context.fillEllipse(in: CGRect(x: point.x - 25, y: point.y - 25, width: 50, height: 50))
    }

    let bitmap = NSBitmapImageRep(cgImage: context.makeImage()!)
    let png = bitmap.representation(using: .png, properties: [:])!
    representationsData.append(iconBlock(type, png))
}
try iconBlock("icns", representationsData).write(to: destination, options: .atomic)
