// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! PDF generation capability
//!
//! Feature-gated PDF generation using printpdf.
//! For full visual rendering, use headless_chrome as fallback.

use std::path::Path;

use crate::dom::Document;
use crate::error::{Error, Result};

/// PDF generation options (CDP-compatible naming)
#[derive(Debug, Clone)]
pub struct PrintToPdfOptions {
    /// Paper width in inches
    pub paper_width: f64,
    /// Paper height in inches
    pub paper_height: f64,
    /// Top margin in inches
    pub margin_top: f64,
    /// Bottom margin in inches
    pub margin_bottom: f64,
    /// Left margin in inches
    pub margin_left: f64,
    /// Right margin in inches
    pub margin_right: f64,
    /// Print background graphics
    pub print_background: bool,
    /// Page scale factor
    pub scale: f64,
    /// Landscape orientation
    pub landscape: bool,
    /// Display header/footer
    pub display_header_footer: bool,
    /// Header template HTML
    pub header_template: Option<String>,
    /// Footer template HTML
    pub footer_template: Option<String>,
    /// Page ranges to print (e.g., "1-3, 5")
    pub page_ranges: Option<String>,
}

impl Default for PrintToPdfOptions {
    fn default() -> Self {
        Self {
            paper_width: 8.5,    // Letter width
            paper_height: 11.0,  // Letter height
            margin_top: 0.4,
            margin_bottom: 0.4,
            margin_left: 0.4,
            margin_right: 0.4,
            print_background: true,
            scale: 1.0,
            landscape: false,
            display_header_footer: false,
            header_template: None,
            footer_template: None,
            page_ranges: None,
        }
    }
}

impl PrintToPdfOptions {
    /// Create options for A4 paper
    pub fn a4() -> Self {
        Self {
            paper_width: 8.27,   // A4 width in inches
            paper_height: 11.69, // A4 height in inches
            ..Default::default()
        }
    }

    /// Create options for Letter paper
    pub fn letter() -> Self {
        Self::default()
    }

    /// Set margins uniformly
    pub fn margins(mut self, margin: f64) -> Self {
        self.margin_top = margin;
        self.margin_bottom = margin;
        self.margin_left = margin;
        self.margin_right = margin;
        self
    }

    /// Set landscape mode
    pub fn landscape(mut self) -> Self {
        self.landscape = true;
        self
    }

    /// Set header template
    pub fn header(mut self, template: impl Into<String>) -> Self {
        self.display_header_footer = true;
        self.header_template = Some(template.into());
        self
    }

    /// Set footer template
    pub fn footer(mut self, template: impl Into<String>) -> Self {
        self.display_header_footer = true;
        self.footer_template = Some(template.into());
        self
    }
}

/// PDF generator trait
pub trait PdfGenerator: Send + Sync {
    /// Generate PDF from HTML content
    fn generate_pdf(
        &self,
        html: &str,
        options: &PrintToPdfOptions,
    ) -> Result<Vec<u8>>;

    /// Generate PDF from document
    fn generate_pdf_from_document(
        &self,
        document: &Document,
        options: &PrintToPdfOptions,
    ) -> Result<Vec<u8>> {
        self.generate_pdf(&document.outer_html(), options)
    }

    /// Save PDF to file
    fn save_pdf(
        &self,
        html: &str,
        path: &Path,
        options: &PrintToPdfOptions,
    ) -> Result<()> {
        let pdf_data = self.generate_pdf(html, options)?;
        std::fs::write(path, pdf_data)?;
        Ok(())
    }
}

/// Simple PDF generator using printpdf (no visual rendering)
///
/// This generates basic PDFs with text content.
/// For full visual rendering, use ChromePdfGenerator.
#[cfg(feature = "pdf")]
pub struct SimplePdfGenerator;

#[cfg(feature = "pdf")]
impl SimplePdfGenerator {
    pub fn new() -> Self {
        Self
    }
}

#[cfg(feature = "pdf")]
impl Default for SimplePdfGenerator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "pdf")]
impl PdfGenerator for SimplePdfGenerator {
    fn generate_pdf(
        &self,
        html: &str,
        options: &PrintToPdfOptions,
    ) -> Result<Vec<u8>> {
        use printpdf::*;

        // Parse HTML to extract text
        let doc = crate::dom::parse_html(html)?;
        let text = doc.text_content();

        // Create PDF document
        let (pdf_doc, page1, layer1) = PdfDocument::new(
            "Report",
            Mm(options.paper_width * 25.4),
            Mm(options.paper_height * 25.4),
            "Layer 1",
        );

        let current_layer = pdf_doc.get_page(page1).get_layer(layer1);

        // Add text (simplified - real implementation would handle layout)
        let font = pdf_doc
            .add_builtin_font(BuiltinFont::Helvetica)
            .map_err(|e| Error::Other(format!("Font error: {:?}", e)))?;

        let margin_left = Mm(options.margin_left * 25.4);
        let margin_top = Mm(options.margin_top * 25.4);
        let page_height = Mm(options.paper_height * 25.4);

        // Simple text rendering
        let lines: Vec<&str> = text.lines().collect();
        let mut y_pos = page_height - margin_top - Mm(12.0);

        for line in lines.iter().take(50) {
            // Limit lines per page
            if !line.trim().is_empty() {
                current_layer.use_text(
                    line.trim(),
                    10.0,
                    margin_left,
                    y_pos,
                    &font,
                );
                y_pos = y_pos - Mm(5.0);

                if y_pos < Mm(options.margin_bottom * 25.4) {
                    break; // Would need to add new page
                }
            }
        }

        // Save to bytes
        let mut buffer = Vec::new();
        pdf_doc
            .save(&mut std::io::BufWriter::new(&mut buffer))
            .map_err(|e| Error::Other(format!("PDF save error: {:?}", e)))?;

        Ok(buffer)
    }
}

/// Chrome-based PDF generator (requires headless_chrome)
///
/// Use this when you need full visual rendering.
#[cfg(feature = "chrome-pdf")]
pub struct ChromePdfGenerator {
    browser: headless_chrome::Browser,
}

#[cfg(feature = "chrome-pdf")]
impl ChromePdfGenerator {
    pub fn new() -> Result<Self> {
        let browser = headless_chrome::Browser::default()
            .map_err(|e| Error::Other(format!("Chrome launch error: {:?}", e)))?;
        Ok(Self { browser })
    }
}

#[cfg(feature = "chrome-pdf")]
impl PdfGenerator for ChromePdfGenerator {
    fn generate_pdf(
        &self,
        html: &str,
        options: &PrintToPdfOptions,
    ) -> Result<Vec<u8>> {
        use headless_chrome::protocol::cdp::Page::PrintToPdfParams;

        let tab = self.browser.new_tab()
            .map_err(|e| Error::Other(format!("Tab error: {:?}", e)))?;

        // Navigate to data URL with HTML
        let data_url = format!(
            "data:text/html;base64,{}",
            base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                html.as_bytes()
            )
        );

        tab.navigate_to(&data_url)
            .map_err(|e| Error::Other(format!("Navigate error: {:?}", e)))?;

        tab.wait_until_navigated()
            .map_err(|e| Error::Other(format!("Wait error: {:?}", e)))?;

        // Generate PDF
        let pdf_options = PrintToPdfParams {
            landscape: Some(options.landscape),
            display_header_footer: Some(options.display_header_footer),
            print_background: Some(options.print_background),
            scale: Some(options.scale),
            paper_width: Some(options.paper_width),
            paper_height: Some(options.paper_height),
            margin_top: Some(options.margin_top),
            margin_bottom: Some(options.margin_bottom),
            margin_left: Some(options.margin_left),
            margin_right: Some(options.margin_right),
            page_ranges: options.page_ranges.clone(),
            header_template: options.header_template.clone(),
            footer_template: options.footer_template.clone(),
            ..Default::default()
        };

        let pdf_data = tab.print_to_pdf(Some(pdf_options))
            .map_err(|e| Error::Other(format!("PDF error: {:?}", e)))?;

        Ok(pdf_data)
    }
}

/// Null PDF generator (when PDF feature is disabled)
pub struct NullPdfGenerator;

impl PdfGenerator for NullPdfGenerator {
    fn generate_pdf(
        &self,
        _html: &str,
        _options: &PrintToPdfOptions,
    ) -> Result<Vec<u8>> {
        Err(Error::Config(
            "PDF generation is disabled. Enable 'pdf' or 'chrome-pdf' feature.".into()
        ))
    }
}

/// Create appropriate PDF generator based on features
pub fn create_pdf_generator() -> Box<dyn PdfGenerator> {
    #[cfg(feature = "chrome-pdf")]
    {
        if let Ok(gen) = ChromePdfGenerator::new() {
            return Box::new(gen);
        }
    }

    #[cfg(feature = "pdf")]
    {
        return Box::new(SimplePdfGenerator::new());
    }

    #[cfg(not(any(feature = "pdf", feature = "chrome-pdf")))]
    {
        Box::new(NullPdfGenerator)
    }
}

/// Report format options
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportFormat {
    /// HTML report
    Html,
    /// PDF report (requires feature)
    Pdf,
    /// JSON data export
    Json,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pdf_options() {
        let opts = PrintToPdfOptions::a4()
            .margins(0.5)
            .landscape();

        assert!(opts.landscape);
        assert_eq!(opts.margin_top, 0.5);
    }
}
