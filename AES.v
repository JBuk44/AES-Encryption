module AES(clk, rst, sevSeg, decrypt, q, r, s, t, u, v, w);
input clk, rst, decrypt;
input [1:0] sevSeg;

output[7:0] q, r, s, t, u, v, w;

reg[7:0] q, r, s, t, u, v, w;
reg[7:0] i [7:0];

reg [7:0] b [3:0][3:0]; //2d array
reg[7:0] bcopy [3:0][3:0];
reg[7:0] lmat [3:0][15:0];
reg[7:0] lconst [3:0][3:0];
reg[7:0] Okey[3:0][3:0];

reg[7:0] key [3:0][43:0];

reg[7:0] lmatRow, lmatCol, ematRow, ematCol;
reg[7:0] sboxRow, sboxCol;
reg [5:0] row, col;

reg[3:0] S, NS;
reg[7:0] NV, LV, EV;

reg[2:0] SR_Part, MC_Part;
reg[8:0] overflow;

reg[1:0] display, round2;
reg[4:0] round;
reg[7:0] rcon [9:0];

reg[7:0] keyCol [3:0][0:0];
reg[3:0] rcount;
reg reset, boolean;

parameter KEYS = 4'd0,
			 SBOX = 4'd1,
			 SROW = 4'd2,
			 MCOL = 4'd3,
			 RKEY = 4'd4,
			 DONE = 4'd5,
			 ERST = 4'd6,
			 DRST = 4'd7;

initial
begin	
	b[0][0] = 8'h50;
	b[0][1] = 8'h6e;
	b[0][2] = 8'h74;
	b[0][3] = 8'h41;
	b[1][0] = 8'h6c;
	b[1][1] = 8'h74;
	b[1][2] = 8'h20;
	b[1][3] = 8'h45;
	b[2][0] = 8'h61;
	b[2][1] = 8'h65;
	b[2][2] = 8'h34;
	b[2][3] = 8'h53;
	b[3][0] = 8'h69;
	b[3][1] = 8'h78;
	b[3][2] = 8'h20;
	b[3][3] = 8'h2e;

//	b[0][0] = 8'h53;
//	b[0][1] = 8'h6e;
//	b[0][2] = 8'h65;
//	b[0][3] = 8'h67;
//	b[1][0] = 8'h65;
//	b[1][1] = 8'h64;
//	b[1][2] = 8'h73;
//	b[1][3] = 8'h65;
//	b[2][0] = 8'h63;
//	b[2][1] = 8'h20;
//	b[2][2] = 8'h73;
//	b[2][3] = 8'h21;
//	b[3][0] = 8'h6f;
//	b[3][1] = 8'h6d;
//	b[3][2] = 8'h61;
//	b[3][3] = 8'h21;

	Okey[0][0] = 8'h54;
	Okey[0][1] = 8'h20;
	Okey[0][2] = 8'h74;
	Okey[0][3] = 8'h6b;
	Okey[1][0] = 8'h68;
	Okey[1][1] = 8'h69;
	Okey[1][2] = 8'h68;
	Okey[1][3] = 8'h65;
	Okey[2][0] = 8'h69;
	Okey[2][1] = 8'h73;
	Okey[2][2] = 8'h65;
	Okey[2][3] = 8'h79;
	Okey[3][0] = 8'h73;
	Okey[3][1] = 8'h20;
	Okey[3][2] = 8'h20;
	Okey[3][3] = 8'h2e;

//	Okey[0][0] = 8'h53;
//	Okey[0][1] = 8'h6e;
//	Okey[0][2] = 8'h65;
//	Okey[0][3] = 8'h20;
//	Okey[1][0] = 8'h65;
//	Okey[1][1] = 8'h64;
//	Okey[1][2] = 8'h79;
//	Okey[1][3] = 8'h75;
//	Okey[2][0] = 8'h63;
//	Okey[2][1] = 8'h20;
//	Okey[2][2] = 8'h20;
//	Okey[2][3] = 8'h73;
//	Okey[3][0] = 8'h6f;
//	Okey[3][1] = 8'h6b;
//	Okey[3][2] = 8'h32;
//	Okey[3][3] = 8'h65;
	
	lconst[0][0] = 8'h19; //02
	lconst[0][1] = 8'h01; //03
	lconst[0][2] = 8'h00; //01
	lconst[0][3] = 8'h00; //01
	lconst[1][0] = 8'h00; //01
	lconst[1][1] = 8'h19; //02
	lconst[1][2] = 8'h01; //03
	lconst[1][3] = 8'h00; //01
	lconst[2][0] = 8'h00; //01
	lconst[2][1] = 8'h00; //01
	lconst[2][2] = 8'h19; //02
	lconst[2][3] = 8'h01; //03
	lconst[3][0] = 8'h01; //03
	lconst[3][1] = 8'h00; //01
	lconst[3][2] = 8'h00; //01
	lconst[3][3] = 8'h19; //02
	
	rcon[0] = 8'h01;
	rcon[1] = 8'h02;
	rcon[2] = 8'h04;
	rcon[3] = 8'h08;
	rcon[4] = 8'h10;
	rcon[5] = 8'h20;
	rcon[6] = 8'h40;
	rcon[7] = 8'h80;
	rcon[8] = 8'h1b;
	rcon[9] = 8'h36;
	
	row = 5'd0;
	col = 6'd0;
	SR_Part = 3'd0;
	MC_Part = 3'd0;
	round = 5'd0;
	display = 2'd0;
	reset = 1'b0;
end

always@(posedge clk or negedge rst)
begin
	if(rst == 1'b0)
	begin
		row <= 5'd0;
		col <= 6'd0;
		
		SR_Part <= 3'd0;
		MC_Part <= 3'd0;
		
		S<=KEYS;

		display <= 2'd0;
		rcon[0] <= rcon[0];
		rcount = 4'd0;
		
		boolean <= 1'b0;
		
		round <= 5'd0;
		reset <= 1'b0;
		
		key[0][0] <= Okey[0][0];
		key[0][1] <= Okey[0][1];
		key[0][2] <= Okey[0][2];
		key[0][3] <= Okey[0][3];
		key[1][0] <= Okey[1][0];
		key[1][1] <= Okey[1][1];
		key[1][2] <= Okey[1][2];
		key[1][3] <= Okey[1][3];
		key[2][0] <= Okey[2][0];
		key[2][1] <= Okey[2][1];
		key[2][2] <= Okey[2][2];
		key[2][3] <= Okey[2][3];
		key[3][0] <= Okey[3][0];
		key[3][1] <= Okey[3][1];
		key[3][2] <= Okey[3][2];
		key[3][3] <= Okey[3][3];
		
		b[0][0] <= 8'h50;
		b[0][1] <= 8'h6e;
		b[0][2] <= 8'h74;
		b[0][3] <= 8'h41;
		b[1][0] <= 8'h6c;
		b[1][1] <= 8'h74;
		b[1][2] <= 8'h20;
		b[1][3] <= 8'h45;
		b[2][0] <= 8'h61;
		b[2][1] <= 8'h65;
		b[2][2] <= 8'h34;
		b[2][3] <= 8'h53;
		b[3][0] <= 8'h69;
		b[3][1] <= 8'h78;
		b[3][2] <= 8'h20;
		b[3][3] <= 8'h2e;

//		b[0][0] <= 8'h53;
//		b[0][1] <= 8'h6e;
//		b[0][2] <= 8'h65;
//		b[0][3] <= 8'h67;
//		b[1][0] <= 8'h65;
//		b[1][1] <= 8'h64;
//		b[1][2] <= 8'h73;
//		b[1][3] <= 8'h65;
//		b[2][0] <= 8'h63;
//		b[2][1] <= 8'h20;
//		b[2][2] <= 8'h73;
//		b[2][3] <= 8'h21;
//		b[3][0] <= 8'h6f;
//		b[3][1] <= 8'h6d;
//		b[3][2] <= 8'h61;
//		b[3][3] <= 8'h21;
	end
	else
	begin
	
		case(S)
			KEYS:
			begin
				if(row == 4'd0 && boolean == 1'b0)
				begin
					keyCol[0][0] <= key[1][col+2'd3];
					keyCol[1][0] <= key[2][col+2'd3];
					keyCol[2][0] <= key[3][col+2'd3];
					keyCol[3][0] <= key[0][col+2'd3];
					
					boolean <= 1'b1;
				end
				else if(row < 4'd7)
				begin
					sboxRow <= keyCol[row-1'b1][0] / 8'h10;
					sboxCol <= keyCol[row-1'b1][0] % 8'h10; 
					
					keyCol[row - 2'd2][0] <= NV;
					
					row <= row + 1'b1;
				end
				else if(row == 4'd7)
				begin
					keyCol[0][0] <= keyCol[0][0]^rcon[rcount];
					
					row <= row + 1'b1;
				end
				else if(row == 4'd8)
				begin		
					key[0][col + 3'd4] <= key[0][col]^keyCol[0][0];
					key[1][col + 3'd4] <= key[1][col]^keyCol[1][0];
					key[2][col + 3'd4] <= key[2][col]^keyCol[2][0];
					key[3][col + 3'd4] <= key[3][col]^keyCol[3][0];
				
					row <= row + 1'b1;
				end
				else if(row == 4'd9)
				begin
					key[0][col + 3'd5] <= key[0][col + 3'd1]^key[0][col + 3'd4];
					key[1][col + 3'd5] <= key[1][col + 3'd1]^key[1][col + 3'd4];
					key[2][col + 3'd5] <= key[2][col + 3'd1]^key[2][col + 3'd4];
					key[3][col + 3'd5] <= key[3][col + 3'd1]^key[3][col + 3'd4];
					
					row <= row + 1'b1;
				end
				else if(row == 4'd10)
				begin
					key[0][col + 3'd6] <= key[0][col + 3'd2]^key[0][col + 3'd5];
					key[1][col + 3'd6] <= key[1][col + 3'd2]^key[1][col + 3'd5];
					key[2][col + 3'd6] <= key[2][col + 3'd2]^key[2][col + 3'd5];
					key[3][col + 3'd6] <= key[3][col + 3'd2]^key[3][col + 3'd5];
					
					row <= row + 1'b1;			
				end
				else
				begin
					key[0][col + 3'd7] <= key[0][col + 3'd3]^key[0][col + 3'd6];
					key[1][col + 3'd7] <= key[1][col + 3'd3]^key[1][col + 3'd6];
					key[2][col + 3'd7] <= key[2][col + 3'd3]^key[2][col + 3'd6];
					key[3][col + 3'd7] <= key[3][col + 3'd3]^key[3][col + 3'd6];
					
					if(col < 6'd33)
					begin
						row <= 5'd0;
						col <= col + 3'd4;
						boolean <= 1'b0;
						rcount <= rcount + 1'b1;
					end
					else
					begin
						row <= 5'd0;
						col <= 6'd0;
						round2 <= round2 + 1'b1;
						display <= 1'b1;
					end
				end	
			end
			SBOX:
			begin
				if(display == 2'd2)
				begin
					display <= 2'd1;
					row <= 5'd0;
					col <= 6'd0;
				end
					
				if(row < 3'd5)
				begin
					sboxRow <= b[row - 1'b1][col] / 8'h10;
					sboxCol <= b[row - 1'b1][col] % 8'h10; 
					
					b[row - 1'b1][col - 1'b1] <= NV;
					
					if(col < 3'd4)
					begin
						col <= col + 1'b1;
					end
					else 
					begin
						col <= 3'b000;
						row <= row + 1'b1;
					end
				end
			end
			SROW:
			begin
				if(SR_Part == 2'd0)
				begin
					display <= 2'd1;
					
					bcopy[0][0] <= b[0][0];
					bcopy[0][1] <= b[0][1];
					bcopy[0][2] <= b[0][2];
					bcopy[0][3] <= b[0][3];
					
					bcopy[1][0] <= b[1][0];
					bcopy[1][1] <= b[1][1];
					bcopy[1][2] <= b[1][2];
					bcopy[1][3] <= b[1][3];
					
					bcopy[2][0] <= b[2][0];
					bcopy[2][1] <= b[2][1];
					bcopy[2][2] <= b[2][2];
					bcopy[2][3] <= b[2][3];
					
					bcopy[3][0] <= b[3][0];
					bcopy[3][1] <= b[3][1];
					bcopy[3][2] <= b[3][2];
					bcopy[3][3] <= b[3][3];
					
					if(decrypt == 1'b1)
					begin
						if(round > 5'd0)
							round <= round - 1'b1;
						else
							round <= 5'd0;
					end
					else
						round <= round;
					
					SR_Part <= SR_Part + 1'b1;
				end
				else
				begin
					if(decrypt == 1'b0)
					begin
						//first row does not change therefor not shown
						b[0][0] <= bcopy[0][0];
						b[0][1] <= bcopy[0][1];
						b[0][2] <= bcopy[0][2];
						b[0][3] <= bcopy[0][3];
						
						b[1][0] <= bcopy[1][1];
						b[1][1] <= bcopy[1][2];
						b[1][2] <= bcopy[1][3];
						b[1][3] <= bcopy[1][0];
						
						b[2][0] <= bcopy[2][2];
						b[2][1] <= bcopy[2][3];
						b[2][2] <= bcopy[2][0];
						b[2][3] <= bcopy[2][1];
						
						b[3][0] <= bcopy[3][3];
						b[3][1] <= bcopy[3][0];
						b[3][2] <= bcopy[3][1];
						b[3][3] <= bcopy[3][2];
						
						col <= 5'd0;
						row <= 5'd0;
						
						SR_Part <= SR_Part + 1'b1;
					end
					else
					begin
						b[0][0] <= bcopy[0][0];
						b[0][1] <= bcopy[0][1];
						b[0][2] <= bcopy[0][2];
						b[0][3] <= bcopy[0][3];
						
						b[1][0] <= bcopy[1][3];
						b[1][1] <= bcopy[1][0];
						b[1][2] <= bcopy[1][1];
						b[1][3] <= bcopy[1][2];
						
						b[2][0] <= bcopy[2][2];
						b[2][1] <= bcopy[2][3];
						b[2][2] <= bcopy[2][0];
						b[2][3] <= bcopy[2][1];
						
						b[3][0] <= bcopy[3][1];
						b[3][1] <= bcopy[3][2];
						b[3][2] <= bcopy[3][3];
						b[3][3] <= bcopy[3][0];
						
						col <= 5'd0;
						row <= 5'd0;
						MC_Part <= 3'd0;
						
						SR_Part <= SR_Part + 1'b1;
					end
				end
			end
			MCOL:
			begin
				if(MC_Part == 3'd0)
				begin
					//intializing the lmatrix 
					//------------------- 1/4
					lmat[0][0] <= b[0][0];
					lmat[0][1] <= b[1][0];
					lmat[0][2] <= b[2][0];
					lmat[0][3] <= b[3][0];
					lmat[1][0] <= b[0][0];
					lmat[1][1] <= b[1][0];
					lmat[1][2] <= b[2][0];
					lmat[1][3] <= b[3][0];
					lmat[2][0] <= b[0][0];
					lmat[2][1] <= b[1][0];
					lmat[2][2] <= b[2][0];
					lmat[2][3] <= b[3][0];
					lmat[3][0] <= b[0][0];
					lmat[3][1] <= b[1][0];
					lmat[3][2] <= b[2][0];
					lmat[3][3] <= b[3][0];
					//------------------- 2/4
					lmat[0][4] <= b[0][1];
					lmat[0][5] <= b[1][1];
					lmat[0][6] <= b[2][1];
					lmat[0][7] <= b[3][1];
					lmat[1][4] <= b[0][1];
					lmat[1][5] <= b[1][1];
					lmat[1][6] <= b[2][1];
					lmat[1][7] <= b[3][1];
					lmat[2][4] <= b[0][1];
					lmat[2][5] <= b[1][1];
					lmat[2][6] <= b[2][1];
					lmat[2][7] <= b[3][1];
					lmat[3][4] <= b[0][1];
					lmat[3][5] <= b[1][1];
					lmat[3][6] <= b[2][1];
					lmat[3][7] <= b[3][1];
					//------------------- 3/4
					lmat[0][8] <= b[0][2];
					lmat[0][9] <= b[1][2];
					lmat[0][10]<= b[2][2];
					lmat[0][11]<= b[3][2];
					lmat[1][8] <= b[0][2];
					lmat[1][9] <= b[1][2];
					lmat[1][10]<= b[2][2];
					lmat[1][11]<= b[3][2];
					lmat[2][8] <= b[0][2];
					lmat[2][9] <= b[1][2];
					lmat[2][10]<= b[2][2];
					lmat[2][11]<= b[3][2];
					lmat[3][8] <= b[0][2];
					lmat[3][9] <= b[1][2];
					lmat[3][10]<= b[2][2];
					lmat[3][11]<= b[3][2];
					//------------------- 4/4
					lmat[0][12]<= b[0][3];
					lmat[0][13]<= b[1][3];
					lmat[0][14]<= b[2][3];
					lmat[0][15]<= b[3][3];
					lmat[1][12]<= b[0][3];
					lmat[1][13]<= b[1][3];
					lmat[1][14]<= b[2][3];
					lmat[1][15]<= b[3][3];
					lmat[2][12]<= b[0][3];
					lmat[2][13]<= b[1][3];
					lmat[2][14]<= b[2][3];
					lmat[2][15]<= b[3][3];
					lmat[3][12]<= b[0][3];
					lmat[3][13]<= b[1][3];
					lmat[3][14]<= b[2][3];
					lmat[3][15]<= b[3][3];
					
					col <= 5'd0;
					row <= 5'd0;
					
					MC_Part <= 3'd1;
				end
				else if(MC_Part == 3'd1)//substitute values for l values
				begin
					if(row < 3'b100)
					begin
						lmatRow <= lmat[row][col] / 8'h10;
						lmatCol <= lmat[row][col] % 8'h10; 
						
						lmat[row][col - 1'b1] <= LV;
						
						if(col < 5'b10000)
						begin
							col <= col + 5'b00001;
						end
						else 
						begin
							col <= 6'd0;
							row <= row + 3'b001;
						end
					end
					else
					begin
						MC_Part <= 3'd2;
						row <= 5'd0;
						col <= 6'd0;
					end
				end
				else if(MC_Part == 3'd2)//add matrix values to each other
				begin
					if(row < 3'd4)
					begin
						
						overflow <= lmat[row][col] + lconst[row][col % 4];
					
						if(overflow > 8'hff)
							lmat[row][col - 1'b1] <= overflow - 8'hff;
						else
							lmat[row][col - 1'b1] <= overflow;
						if(col < 5'b10000)
						begin
							col <= col + 5'b00001;
						end
						else 
						begin
							col <= 6'd0;
							row <= row + 3'b001;
						end
					end
					else
					begin
						MC_Part <= MC_Part + 3'd1;
						row <= 5'd0;
						col <= 6'd0;
					end
				end
				else if(MC_Part == 3'd3) //take values through the etable
				begin
					if(row < 3'b100)
					begin
						//going through each of the 4 4x4 matrices in the 4 x 16 through e table
						ematRow <= lmat[row][col] / 8'h10;
						ematCol <= lmat[row][col] % 8'h10;
						
						lmat[row][col - 1'b1] <= EV;
						
						if(col < 5'b10000)
						begin
							col <= col + 5'b00001;
						end
						else 
						begin
							col <= 6'd0;
							row <= row + 3'b001;
						end
					end
					else
					begin
						MC_Part <= MC_Part + 3'd1;
						row <= 5'd0;
						col <= 6'd0;
					end
				end
				else
				begin
					if(row < 3'b001)
					begin
						b[0][0] <= lmat[0][0]^lmat[0][1]^lmat[0][2]^lmat[0][3];
						b[0][1] <= lmat[0][4]^lmat[0][5]^lmat[0][6]^lmat[0][7];
						b[0][2] <= lmat[0][8]^lmat[0][9]^lmat[0][10]^lmat[0][11];
						b[0][3] <= lmat[0][12]^lmat[0][13]^lmat[0][14]^lmat[0][15];	
						
						b[1][0] <= lmat[1][0]^lmat[1][1]^lmat[1][2]^lmat[1][3];
						b[1][1] <= lmat[1][4]^lmat[1][5]^lmat[1][6]^lmat[1][7];
						b[1][2] <= lmat[1][8]^lmat[1][9]^lmat[1][10]^lmat[1][11];
						b[1][3] <= lmat[1][12]^lmat[1][13]^lmat[1][14]^lmat[1][15];
						
						b[2][0] <= lmat[2][0]^lmat[2][1]^lmat[2][2]^lmat[2][3];
						b[2][1] <= lmat[2][4]^lmat[2][5]^lmat[2][6]^lmat[2][7];
						b[2][2] <= lmat[2][8]^lmat[2][9]^lmat[2][10]^lmat[2][11];
						b[2][3] <= lmat[2][12]^lmat[2][13]^lmat[2][14]^lmat[2][15];
						
						b[3][0] <= lmat[3][0]^lmat[3][1]^lmat[3][2]^lmat[3][3];
						b[3][1] <= lmat[3][4]^lmat[3][5]^lmat[3][6]^lmat[3][7];
						b[3][2] <= lmat[3][8]^lmat[3][9]^lmat[3][10]^lmat[3][11];
						b[3][3] <= lmat[3][12]^lmat[3][13]^lmat[3][14]^lmat[3][15];	
						row <= row + 3'b001;
						MC_Part <= MC_Part + 3'd1;
						display <= 2'd1;	
					end
				end
			end
			RKEY:
			begin
				if(display == 2'd1)
				begin
						b[0][0] <= b[0][0]^key[0][round * 3'd4];
						b[0][1] <= b[0][1]^key[0][round * 3'd4 + 1'b1];
						b[0][2] <= b[0][2]^key[0][round * 3'd4 + 2'd2];
						b[0][3] <= b[0][3]^key[0][round * 3'd4 + 2'd3];
						
						b[1][0] <= b[1][0]^key[1][round * 3'd4];
						b[1][1] <= b[1][1]^key[1][round * 3'd4 + 1'b1];
						b[1][2] <= b[1][2]^key[1][round * 3'd4 + 2'd2];
						b[1][3] <= b[1][3]^key[1][round * 3'd4 + 2'd3];
						
						b[2][0] <= b[2][0]^key[2][round * 3'd4];
						b[2][1] <= b[2][1]^key[2][round * 3'd4 + 1'b1];
						b[2][2] <= b[2][2]^key[2][round * 3'd4 + 2'd2];
						b[2][3] <= b[2][3]^key[2][round * 3'd4 + 2'd3];
						
						b[3][0] <= b[3][0]^key[3][round * 3'd4];
						b[3][1] <= b[3][1]^key[3][round * 3'd4 + 1'b1];
						b[3][2] <= b[3][2]^key[3][round * 3'd4 + 2'd2];
						b[3][3] <= b[3][3]^key[3][round * 3'd4 + 2'd3];
					
					if(decrypt == 1'b0)
						round <= round + 1'b1;
					else
					begin
						round <= round;
					end
					
					row <= 5'd0;
					col <= 5'd0;
					display <= 2'd2;
					SR_Part <= 3'd0;
					MC_Part <= 3'd0;
				end
			end
			ERST:
			begin
				key[0][0] <= Okey[0][0];
				key[0][1] <= Okey[0][1];
				key[0][2] <= Okey[0][2];
				key[0][3] <= Okey[0][3];
				key[1][0] <= Okey[1][0];
				key[1][1] <= Okey[1][1];
				key[1][2] <= Okey[1][2];
				key[1][3] <= Okey[1][3];
				key[2][0] <= Okey[2][0];
				key[2][1] <= Okey[2][1];
				key[2][2] <= Okey[2][2];
				key[2][3] <= Okey[2][3];
				key[3][0] <= Okey[3][0];
				key[3][1] <= Okey[3][1];
				key[3][2] <= Okey[3][2];
				key[3][3] <= Okey[3][3];
				
				lconst[0][0] <= 8'h19; //02
				lconst[0][1] <= 8'h01; //03
				lconst[0][2] <= 8'h00; //01
				lconst[0][3] <= 8'h00; //01
				lconst[1][0] <= 8'h00; //01
				lconst[1][1] <= 8'h19; //02
				lconst[1][2] <= 8'h01; //03
				lconst[1][3] <= 8'h00; //01
				lconst[2][0] <= 8'h00; //01
				lconst[2][1] <= 8'h00; //01
				lconst[2][2] <= 8'h19; //02
				lconst[2][3] <= 8'h01; //03
				lconst[3][0] <= 8'h01; //03
				lconst[3][1] <= 8'h00; //01
				lconst[3][2] <= 8'h00; //01
				lconst[3][3] <= 8'h19; //02
				
				round <= 5'd0;
				
				reset <= 1'b0;
				
				row <= 5'd0;
				col <= 6'd0;
				
				SR_Part <= 3'd0;
				MC_Part <= 3'd0;
				display <= 2'd1;
				
				rcount <= 4'd0;
				boolean <= 1'b0;
			end
			DRST:
			begin
				lconst[0][0] <= 8'hdf; //0e
				lconst[0][1] <= 8'h68; //0b
				lconst[0][2] <= 8'hee; //0d
				lconst[0][3] <= 8'hc7; //09
				lconst[1][0] <= 8'hc7; //09
				lconst[1][1] <= 8'hdf; //0e
				lconst[1][2] <= 8'h68; //0b
				lconst[1][3] <= 8'hee; //0d
				lconst[2][0] <= 8'hee; //0d
				lconst[2][1] <= 8'hc7; //09
				lconst[2][2] <= 8'hdf; //0e
				lconst[2][3] <= 8'h68; //0b
				lconst[3][0] <= 8'h68; //0b
				lconst[3][1] <= 8'hee; //0d
				lconst[3][2] <= 8'hc7; //09
				lconst[3][3] <= 8'hdf; //0e
				
				round <= round - 1'b1;
				
				reset <= 1'b1;
				
				row <= 5'd0;
				col <= 6'd0;
				
				SR_Part <= 3'd0;
				MC_Part <= 3'd0;
				display <= 2'd1;
			end
			default: 
			begin
				b[0][0] <= b[0][0];
				b[0][1] <= b[0][1];
				b[0][2] <= b[0][2];
				b[0][3] <= b[0][3];
				
				b[1][0] <= b[1][0];
				b[1][1] <= b[1][1];
				b[1][2] <= b[1][2];
				b[1][3] <= b[1][3];
				
				b[2][0] <= b[2][0];
				b[2][1] <= b[2][1];
				b[2][2] <= b[2][2];
				b[2][3] <= b[2][3];
				
				b[3][0] <= b[3][0];
				b[3][1] <= b[3][1];
				b[3][2] <= b[3][2];
				b[3][3] <= b[3][3];
			end
		endcase
		S <= NS;
	end
end

always@(*)
begin

	case(S)
	
		KEYS:
		begin
			if(display == 2'd1)
			begin
				if(decrypt == 1'b0)
					NS = ERST;
				else
					NS = DRST;
			end
			else
				NS = KEYS;
		end
		
		SBOX:
		begin
			if(row < 3'd5)
				NS = SBOX;
			else
			begin
				if(decrypt == 1'b0)
					NS = SROW;
				else
					NS = RKEY;
			end
		end
		
		SROW:
		begin
			if(SR_Part < 2'd2)
				NS = SROW;
			else
			begin
				if(round == 5'd10)
				begin
					if(decrypt == 1'b0)
						NS = RKEY;
					else
						NS = SBOX;
				end
				else
				begin
					if(decrypt == 1'b0)
						NS = MCOL;
					else
						NS = SBOX;
				end
			end
		end
		
		MCOL:
		begin
			if(MC_Part < 3'd4)
				NS = MCOL;
			else
			begin
				if(decrypt == 1'b0)
					NS = RKEY;
				else
					NS = SROW;
			end
		end
		
		RKEY:
		begin
			if(display == 2'd2)
			begin
				if(decrypt == 1'b0)
				begin
					if(round < 5'd4)
						NS = SBOX;
					else
						NS = DONE;
				end
				else
				begin
					if(round > 5'd0)
					begin
						if(round == 5'd10)
							NS = SROW;
						else
							NS = MCOL;
					end
					else
						NS = DONE;
				end
			end
			else
				NS = RKEY;
		end
		
		DONE:
		begin
			if(decrypt == 1'b1 && reset == 1'b0)
				NS = DRST;
			else if(decrypt == 1'b0 && reset == 1'b1)
				NS = ERST;
			else
				NS = DONE;
		end
		
		ERST: NS = RKEY;
		DRST: NS = RKEY;
		
		default: NS = DONE;
	endcase

	//SBOX---------------------------------------------------------------
	if(decrypt == 1'b0)
	begin
		case(sboxRow)
		4'h0: 
			case(sboxCol)
			4'h0: NV = 8'h63;
			4'h1: NV = 8'h7c;
			4'h2: NV = 8'h77;
			4'h3: NV = 8'h7b;
			4'h4: NV = 8'hf2;
			4'h5: NV = 8'h6b;
			4'h6: NV = 8'h6f;
			4'h7: NV = 8'hc5;
			4'h8: NV = 8'h30;
			4'h9: NV = 8'h01;
			4'ha: NV = 8'h67;
			4'hb: NV = 8'h2b;
			4'hc: NV = 8'hfe;
			4'hd: NV = 8'hd7;
			4'he: NV = 8'hab;
			4'hf: NV = 8'h76;
			default: NV = 8'hee;
			endcase
		4'h1: 
			case(sboxCol)
			4'h0: NV = 8'hca;
			4'h1: NV = 8'h82;
			4'h2: NV = 8'hc9;
			4'h3: NV = 8'h7d;
			4'h4: NV = 8'hfa;
			4'h5: NV = 8'h59;
			4'h6: NV = 8'h47;
			4'h7: NV = 8'hf0;
			4'h8: NV = 8'had;
			4'h9: NV = 8'hd4;
			4'ha: NV = 8'ha2;
			4'hb: NV = 8'haf;
			4'hc: NV = 8'h9c;
			4'hd: NV = 8'ha4;
			4'he: NV = 8'h72;
			4'hf: NV = 8'hc0;
			default: NV = 8'hee;
			endcase
		4'h2:
			case(sboxCol)
			4'h0: NV = 8'hb7;
			4'h1: NV = 8'hfd;
			4'h2: NV = 8'h93;
			4'h3: NV = 8'h26;
			4'h4: NV = 8'h36;
			4'h5: NV = 8'h3f;
			4'h6: NV = 8'hf7;
			4'h7: NV = 8'hcc;
			4'h8: NV = 8'h34;
			4'h9: NV = 8'ha5;
			4'ha: NV = 8'he5;
			4'hb: NV = 8'hf1;
			4'hc: NV = 8'h71;
			4'hd: NV = 8'hd8;
			4'he: NV = 8'h31;
			4'hf: NV = 8'h15;
			default: NV = 8'hee;
			endcase
		4'h3:
			case(sboxCol)
			4'h0: NV = 8'h04;
			4'h1: NV = 8'hc7;
			4'h2: NV = 8'h23;
			4'h3: NV = 8'hc3;
			4'h4: NV = 8'h18;
			4'h5: NV = 8'h96;
			4'h6: NV = 8'h05;
			4'h7: NV = 8'h9a;
			4'h8: NV = 8'h07;
			4'h9: NV = 8'h12;
			4'ha: NV = 8'h80;
			4'hb: NV = 8'he2;
			4'hc: NV = 8'heb;
			4'hd: NV = 8'h27;
			4'he: NV = 8'hb2;
			4'hf: NV = 8'h75;
			default: NV = 8'hee;
			endcase
		4'h4:
			case(sboxCol)
			4'h0: NV = 8'h09;
			4'h1: NV = 8'h83;
			4'h2: NV = 8'h2c;
			4'h3: NV = 8'h1a;
			4'h4: NV = 8'h1b;
			4'h5: NV = 8'h6e;
			4'h6: NV = 8'h5a;
			4'h7: NV = 8'ha0;
			4'h8: NV = 8'h52;
			4'h9: NV = 8'h3b;
			4'ha: NV = 8'hd6;
			4'hb: NV = 8'hb3;
			4'hc: NV = 8'h29;
			4'hd: NV = 8'he3;
			4'he: NV = 8'h2f;
			4'hf: NV = 8'h84;
			default: NV = 8'hee;
			endcase
		4'h5:
			case(sboxCol)
			4'h0: NV = 8'h53;
			4'h1: NV = 8'hd1;
			4'h2: NV = 8'h00;
			4'h3: NV = 8'hed;
			4'h4: NV = 8'h20;
			4'h5: NV = 8'hfc;
			4'h6: NV = 8'hb1;
			4'h7: NV = 8'h5b;
			4'h8: NV = 8'h6a;
			4'h9: NV = 8'hcb;
			4'ha: NV = 8'hbe;
			4'hb: NV = 8'h39;
			4'hc: NV = 8'h4a;
			4'hd: NV = 8'h4c;
			4'he: NV = 8'h58;
			4'hf: NV = 8'hcf;
			default: NV = 8'hee;
			endcase
		4'h6:
			case(sboxCol)
			4'h0: NV = 8'hd0;
			4'h1: NV = 8'hef;
			4'h2: NV = 8'haa;
			4'h3: NV = 8'hfb;
			4'h4: NV = 8'h43;
			4'h5: NV = 8'h4d;
			4'h6: NV = 8'h33;
			4'h7: NV = 8'h85;
			4'h8: NV = 8'h45;
			4'h9: NV = 8'hf9;
			4'ha: NV = 8'h02;
			4'hb: NV = 8'h7f;
			4'hc: NV = 8'h50;
			4'hd: NV = 8'h3c;
			4'he: NV = 8'h9f;
			4'hf: NV = 8'ha8;
			default: NV = 8'hee;
			endcase
		4'h7:
			case(sboxCol)
			4'h0: NV = 8'h51;
			4'h1: NV = 8'ha3;
			4'h2: NV = 8'h40;
			4'h3: NV = 8'h8f;
			4'h4: NV = 8'h92;
			4'h5: NV = 8'h9d;
			4'h6: NV = 8'h38;
			4'h7: NV = 8'hf5;
			4'h8: NV = 8'hbc;
			4'h9: NV = 8'hb6;
			4'ha: NV = 8'hda;
			4'hb: NV = 8'h21;
			4'hc: NV = 8'h10;
			4'hd: NV = 8'hff;
			4'he: NV = 8'hf3;
			4'hf: NV = 8'hd2;
			default: NV = 8'hee;
			endcase
		4'h8:
			case(sboxCol)
			4'h0: NV = 8'hcd;
			4'h1: NV = 8'h0c;
			4'h2: NV = 8'h13;
			4'h3: NV = 8'hec;
			4'h4: NV = 8'h5f;
			4'h5: NV = 8'h97;
			4'h6: NV = 8'h44;
			4'h7: NV = 8'h17;
			4'h8: NV = 8'hc4;
			4'h9: NV = 8'ha7;
			4'ha: NV = 8'h7e;
			4'hb: NV = 8'h3d;
			4'hc: NV = 8'h64;
			4'hd: NV = 8'h5d;
			4'he: NV = 8'h19;
			4'hf: NV = 8'h73;
			default: NV = 8'hee;
			endcase
		4'h9:
			case(sboxCol)
			4'h0: NV = 8'h60;
			4'h1: NV = 8'h81;
			4'h2: NV = 8'h4f;
			4'h3: NV = 8'hdc;
			4'h4: NV = 8'h22;
			4'h5: NV = 8'h2a;
			4'h6: NV = 8'h90;
			4'h7: NV = 8'h88;
			4'h8: NV = 8'h46;
			4'h9: NV = 8'hee;
			4'ha: NV = 8'hb8;
			4'hb: NV = 8'h14;
			4'hc: NV = 8'hde;
			4'hd: NV = 8'h5e;
			4'he: NV = 8'h0b;
			4'hf: NV = 8'hdb;
			default: NV = 8'hee;
			endcase
		4'ha:
			case(sboxCol)
			4'h0: NV = 8'he0;
			4'h1: NV = 8'h32;
			4'h2: NV = 8'h3a;
			4'h3: NV = 8'h0a;
			4'h4: NV = 8'h49;
			4'h5: NV = 8'h06;
			4'h6: NV = 8'h24;
			4'h7: NV = 8'h5c;
			4'h8: NV = 8'hc2;
			4'h9: NV = 8'hd3;
			4'ha: NV = 8'hac;
			4'hb: NV = 8'h62;
			4'hc: NV = 8'h91;
			4'hd: NV = 8'h95;
			4'he: NV = 8'he4;
			4'hf: NV = 8'h79;
			default: NV = 8'hee;
			endcase
		4'hb:
			case(sboxCol)
			4'h0: NV = 8'he7;
			4'h1: NV = 8'hc8;
			4'h2: NV = 8'h37;
			4'h3: NV = 8'h6d;
			4'h4: NV = 8'h8d;
			4'h5: NV = 8'hd5;
			4'h6: NV = 8'h4e;
			4'h7: NV = 8'ha9;
			4'h8: NV = 8'h6c;
			4'h9: NV = 8'h56;
			4'ha: NV = 8'hf4;
			4'hb: NV = 8'hea;
			4'hc: NV = 8'h65;
			4'hd: NV = 8'h7a;
			4'he: NV = 8'hae;
			4'hf: NV = 8'h08;
			default: NV = 8'hee;
			endcase
		4'hc:
			case(sboxCol)
			4'h0: NV = 8'hba;
			4'h1: NV = 8'h78;
			4'h2: NV = 8'h25;
			4'h3: NV = 8'h2e;
			4'h4: NV = 8'h1c;
			4'h5: NV = 8'ha6;
			4'h6: NV = 8'hb4;
			4'h7: NV = 8'hc6;
			4'h8: NV = 8'he8;
			4'h9: NV = 8'hdd;
			4'ha: NV = 8'h74;
			4'hb: NV = 8'h1f;
			4'hc: NV = 8'h4b;
			4'hd: NV = 8'hbd;
			4'he: NV = 8'h8b;
			4'hf: NV = 8'h8a;
			default: NV = 8'hee;
			endcase
		4'hd:
			case(sboxCol)
			4'h0: NV = 8'h70;
			4'h1: NV = 8'h3e;
			4'h2: NV = 8'hb5;
			4'h3: NV = 8'h66;
			4'h4: NV = 8'h48;
			4'h5: NV = 8'h03;
			4'h6: NV = 8'hf6;
			4'h7: NV = 8'h0e;
			4'h8: NV = 8'h61;
			4'h9: NV = 8'h35;
			4'ha: NV = 8'h57;
			4'hb: NV = 8'hb9;
			4'hc: NV = 8'h86;
			4'hd: NV = 8'hc1;
			4'he: NV = 8'h1d;
			4'hf: NV = 8'h9e;
			default: NV = 8'hee;
			endcase
		4'he:
			case(sboxCol)
			4'h0: NV = 8'he1;
			4'h1: NV = 8'hf8;
			4'h2: NV = 8'h98;
			4'h3: NV = 8'h11;
			4'h4: NV = 8'h69;
			4'h5: NV = 8'hd9;
			4'h6: NV = 8'h8e;
			4'h7: NV = 8'h94;
			4'h8: NV = 8'h9b;
			4'h9: NV = 8'h1e;
			4'ha: NV = 8'h87;
			4'hb: NV = 8'he9;
			4'hc: NV = 8'hce;
			4'hd: NV = 8'h55;
			4'he: NV = 8'h28;
			4'hf: NV = 8'hdf;
			default: NV = 8'hee;
			endcase
		4'hf:
			case(sboxCol)
			4'h0: NV = 8'h8c;
			4'h1: NV = 8'ha1;
			4'h2: NV = 8'h89;
			4'h3: NV = 8'h0d;
			4'h4: NV = 8'hbf;
			4'h5: NV = 8'he6;
			4'h6: NV = 8'h42;
			4'h7: NV = 8'h68;
			4'h8: NV = 8'h41;
			4'h9: NV = 8'h99;
			4'ha: NV = 8'h2d;
			4'hb: NV = 8'h0f;
			4'hc: NV = 8'hb0;
			4'hd: NV = 8'h54;
			4'he: NV = 8'hbb;
			4'hf: NV = 8'h16;
			default: NV = 8'hee;
			endcase
		default: NV = 8'hdd;
		endcase
	end
	else //inverse sbox
	begin
		case(sboxRow)
		4'h0:
			case(sboxCol)
			4'h0: NV = 8'h52;
			4'h1: NV = 8'h09;
			4'h2: NV = 8'h6a;
			4'h3: NV = 8'hd5;
			4'h4: NV = 8'h30;
			4'h5: NV = 8'h36;
			4'h6: NV = 8'ha5;
			4'h7: NV = 8'h38;
			4'h8: NV = 8'hbf;
			4'h9: NV = 8'h40;
			4'ha: NV = 8'ha3;
			4'hb: NV = 8'h9e;
			4'hc: NV = 8'h81;
			4'hd: NV = 8'hf3;
			4'he: NV = 8'hd7;
			4'hf: NV = 8'hfb;
			default: NV = 8'hee;
			endcase
		4'h1:
			case(sboxCol)
			4'h0: NV = 8'h7c;
			4'h1: NV = 8'he3;
			4'h2: NV = 8'h39;
			4'h3: NV = 8'h82;
			4'h4: NV = 8'h9b;
			4'h5: NV = 8'h2f;
			4'h6: NV = 8'hff;
			4'h7: NV = 8'h87;
			4'h8: NV = 8'h34;
			4'h9: NV = 8'h8e;
			4'ha: NV = 8'h43;
			4'hb: NV = 8'h44;
			4'hc: NV = 8'hc4;
			4'hd: NV = 8'hde;
			4'he: NV = 8'he9;
			4'hf: NV = 8'hcb;
			default: NV = 8'hee;
			endcase
		4'h2: 
			case(sboxCol)
			4'h0: NV = 8'h54;
			4'h1: NV = 8'h7b;
			4'h2: NV = 8'h94;
			4'h3: NV = 8'h32;
			4'h4: NV = 8'ha6;
			4'h5: NV = 8'hc2;
			4'h6: NV = 8'h23;
			4'h7: NV = 8'h3d;
			4'h8: NV = 8'hee;
			4'h9: NV = 8'h4c;
			4'ha: NV = 8'h95;
			4'hb: NV = 8'h0b;
			4'hc: NV = 8'h42;
			4'hd: NV = 8'hfa;
			4'he: NV = 8'hc3;
			4'hf: NV = 8'h4e;
			default: NV = 8'hee;
			endcase
		4'h3:
			case(sboxCol)
			4'h0: NV = 8'h08;
			4'h1: NV = 8'h2e;
			4'h2: NV = 8'ha1;
			4'h3: NV = 8'h66;
			4'h4: NV = 8'h28;
			4'h5: NV = 8'hd9;
			4'h6: NV = 8'h24;
			4'h7: NV = 8'hb2;
			4'h8: NV = 8'h76;
			4'h9: NV = 8'hb5;
			4'ha: NV = 8'ha2;
			4'hb: NV = 8'h49;
			4'hc: NV = 8'h6d;
			4'hd: NV = 8'h8b;
			4'he: NV = 8'hd1;
			4'hf: NV = 8'h25;
			default: NV = 8'hee;
			endcase
		4'h4:
			case(sboxCol)
			4'h0: NV = 8'h72; 
			4'h1: NV = 8'hf8;
			4'h2: NV = 8'hf6;
			4'h3: NV = 8'h64;
			4'h4: NV = 8'h86;
			4'h5: NV = 8'h68;
			4'h6: NV = 8'h96;
			4'h7: NV = 8'h16;
			4'h8: NV = 8'hd4;
			4'h9: NV = 8'ha4;
			4'ha: NV = 8'h5c;
			4'hb: NV = 8'hcc;
			4'hc: NV = 8'h5d;
			4'hd: NV = 8'h65;
			4'he: NV = 8'hb6;
			4'hf: NV = 8'h92;
			default: NV = 8'hee;
			endcase
		4'h5:
			case(sboxCol)
			4'h0: NV = 8'h6c;
			4'h1: NV = 8'h70;
			4'h2: NV = 8'h48;
			4'h3: NV = 8'h50;
			4'h4: NV = 8'hfd;
			4'h5: NV = 8'hed;
			4'h6: NV = 8'hb9;
			4'h7: NV = 8'hda;
			4'h8: NV = 8'h5e;
			4'h9: NV = 8'h15;
			4'ha: NV = 8'h46;
			4'hb: NV = 8'h57;
			4'hc: NV = 8'ha7;
			4'hd: NV = 8'h8d;
			4'he: NV = 8'h9d;
			4'hf: NV = 8'h84;
			default: NV = 8'hee;
			endcase
		4'h6:
			case(sboxCol)
			4'h0: NV = 8'h90;
			4'h1: NV = 8'hd8;
			4'h2: NV = 8'hab;
			4'h3: NV = 8'h00;
			4'h4: NV = 8'h8c;
			4'h5: NV = 8'hbc;
			4'h6: NV = 8'hd3;
			4'h7: NV = 8'h0a;
			4'h8: NV = 8'hf7;
			4'h9: NV = 8'he4;
			4'ha: NV = 8'h58;
			4'hb: NV = 8'h05;
			4'hc: NV = 8'hb8;
			4'hd: NV = 8'hb3;
			4'he: NV = 8'h45;
			4'hf: NV = 8'h06;
			default: NV = 8'hee;
			endcase
		4'h7:
			case(sboxCol)
			4'h0: NV = 8'hd0;
			4'h1: NV = 8'h2c;
			4'h2: NV = 8'h1e;
			4'h3: NV = 8'h8f;
			4'h4: NV = 8'hca;
			4'h5: NV = 8'h3f;
			4'h6: NV = 8'h0f;
			4'h7: NV = 8'h02;
			4'h8: NV = 8'hc1;
			4'h9: NV = 8'haf;
			4'ha: NV = 8'hbd;
			4'hb: NV = 8'h03;
			4'hc: NV = 8'h01;
			4'hd: NV = 8'h13;
			4'he: NV = 8'h8a;
			4'hf: NV = 8'h6b;
			default: NV = 8'hee;
			endcase
		4'h8:
			case(sboxCol)
			4'h0: NV = 8'h3a;
			4'h1: NV = 8'h91;
			4'h2: NV = 8'h11;
			4'h3: NV = 8'h41;
			4'h4: NV = 8'h4f;
			4'h5: NV = 8'h67;
			4'h6: NV = 8'hdc;
			4'h7: NV = 8'hea;
			4'h8: NV = 8'h97;
			4'h9: NV = 8'hf2;
			4'ha: NV = 8'hcf;
			4'hb: NV = 8'hce;
			4'hc: NV = 8'hf0;
			4'hd: NV = 8'hb4;
			4'he: NV = 8'he6;
			4'hf: NV = 8'h73;
			default: NV = 8'hee;
			endcase
		4'h9:
			case(sboxCol)
			4'h0: NV = 8'h96;
			4'h1: NV = 8'hac;
			4'h2: NV = 8'h74;
			4'h3: NV = 8'h22;
			4'h4: NV = 8'he7;
			4'h5: NV = 8'had;
			4'h6: NV = 8'h35;
			4'h7: NV = 8'h85;
			4'h8: NV = 8'he2;
			4'h9: NV = 8'hf9;
			4'ha: NV = 8'h37;
			4'hb: NV = 8'he8;
			4'hc: NV = 8'h1c;
			4'hd: NV = 8'h75;
			4'he: NV = 8'hdf;
			4'hf: NV = 8'h6e;
			default: NV = 8'hee;
			endcase
		4'ha:
			case(sboxCol)
			4'h0: NV = 8'h47;
			4'h1: NV = 8'hf1;
			4'h2: NV = 8'h1a;
			4'h3: NV = 8'h71;
			4'h4: NV = 8'h1d;
			4'h5: NV = 8'h29;
			4'h6: NV = 8'hc5;
			4'h7: NV = 8'h89;
			4'h8: NV = 8'h6f;
			4'h9: NV = 8'hb7;
			4'ha: NV = 8'h62;
			4'hb: NV = 8'h0e;
			4'hc: NV = 8'haa;
			4'hd: NV = 8'h18;
			4'he: NV = 8'hbe;
			4'hf: NV = 8'h1b;
			default: NV = 8'hee;
			endcase
		4'hb:
			case(sboxCol)
			4'h0: NV = 8'hfc;
			4'h1: NV = 8'h56;
			4'h2: NV = 8'h3e;
			4'h3: NV = 8'h4b;
			4'h4: NV = 8'hc6;
			4'h5: NV = 8'hd2;
			4'h6: NV = 8'h79;
			4'h7: NV = 8'h20;
			4'h8: NV = 8'h9a;
			4'h9: NV = 8'hdb;
			4'ha: NV = 8'hc0;
			4'hb: NV = 8'hfe;
			4'hc: NV = 8'h78;
			4'hd: NV = 8'hcd;
			4'he: NV = 8'h5a;
			4'hf: NV = 8'hf4;
			default: NV = 8'hee;
			endcase
		4'hc:
			case(sboxCol)
			4'h0: NV = 8'h1f;
			4'h1: NV = 8'hdd;
			4'h2: NV = 8'ha8;
			4'h3: NV = 8'h33;
			4'h4: NV = 8'h88;
			4'h5: NV = 8'h07;
			4'h6: NV = 8'hc7;
			4'h7: NV = 8'h31;
			4'h8: NV = 8'hb1;
			4'h9: NV = 8'h12;
			4'ha: NV = 8'h10;
			4'hb: NV = 8'h59;
			4'hc: NV = 8'h27;
			4'hd: NV = 8'h80;
			4'he: NV = 8'hec;
			4'hf: NV = 8'h5f;
			default: NV = 8'hee;
			endcase
		4'hd:
			case(sboxCol)
			4'h0: NV = 8'h60;
			4'h1: NV = 8'h51;
			4'h2: NV = 8'h7f;
			4'h3: NV = 8'ha9;
			4'h4: NV = 8'h19;
			4'h5: NV = 8'hb5;
			4'h6: NV = 8'h4a;
			4'h7: NV = 8'h0d;
			4'h8: NV = 8'h2d;
			4'h9: NV = 8'he5;
			4'ha: NV = 8'h7a;
			4'hb: NV = 8'h9f;
			4'hc: NV = 8'h93;
			4'hd: NV = 8'hc9;
			4'he: NV = 8'h9c;
			4'hf: NV = 8'hef;
			default: NV = 8'hee;
			endcase
		4'he:
			case(sboxCol)
			4'h0: NV = 8'ha0;
			4'h1: NV = 8'he0;
			4'h2: NV = 8'h3b;
			4'h3: NV = 8'h4d;
			4'h4: NV = 8'hae;
			4'h5: NV = 8'h2a;
			4'h6: NV = 8'hf5;
			4'h7: NV = 8'hb0;
			4'h8: NV = 8'hc8;
			4'h9: NV = 8'heb;
			4'ha: NV = 8'hbb;
			4'hb: NV = 8'h3c;
			4'hc: NV = 8'h83;
			4'hd: NV = 8'h53;
			4'he: NV = 8'h99;
			4'hf: NV = 8'h61;
			default: NV = 8'hee;
			endcase
		4'hf:
			case(sboxCol)
			4'h0: NV = 8'h17;
			4'h1: NV = 8'h2b;
			4'h2: NV = 8'h04;
			4'h3: NV = 8'h7e;
			4'h4: NV = 8'hba;
			4'h5: NV = 8'h77;
			4'h6: NV = 8'hd6;
			4'h7: NV = 8'h26;
			4'h8: NV = 8'he1;
			4'h9: NV = 8'h69;
			4'ha: NV = 8'h14;
			4'hb: NV = 8'h63;
			4'hc: NV = 8'h55;
			4'hd: NV = 8'h21;
			4'he: NV = 8'h0c;
			4'hf: NV = 8'h7d;
			default: NV = 8'hee;
			endcase
			default: NV = 8'hee;
		endcase
	end
	
	//LTABLE ----------------------------------------------------------------
	case (lmatRow)
	4'h0:
		case(lmatCol)
		4'h0: LV = 8'h00;//null
		4'h1: LV = 8'h00;
		4'h2: LV = 8'h19;
		4'h3: LV = 8'h01;
		4'h4: LV = 8'h32;
		4'h5: LV = 8'h02;
		4'h6: LV = 8'h1a;
		4'h7: LV = 8'hc6;
		4'h8: LV = 8'h4b;
		4'h9: LV = 8'hc7;
		4'ha: LV = 8'h1b;
		4'hb: LV = 8'h68;
		4'hc: LV = 8'h33;
		4'hd: LV = 8'hee;
		4'he: LV = 8'hdf;
		4'hf: LV = 8'h03;
		default: LV = 8'hee;
		endcase
	4'h1:
		case(lmatCol)
		4'h0: LV = 8'h64;
		4'h1: LV = 8'h04;
		4'h2: LV = 8'he0;
		4'h3: LV = 8'h0e;
		4'h4: LV = 8'h34;
		4'h5: LV = 8'h8d;
		4'h6: LV = 8'h81;
		4'h7: LV = 8'hef;
		4'h8: LV = 8'h4c;
		4'h9: LV = 8'h71;
		4'ha: LV = 8'h08;
		4'hb: LV = 8'hc8;
		4'hc: LV = 8'hf8;
		4'hd: LV = 8'h69;
		4'he: LV = 8'h1c;
		4'hf: LV = 8'hc1;
		default: LV = 8'hee;
		endcase
	4'h2:
		case(lmatCol)
		4'h0: LV = 8'h7d;
		4'h1: LV = 8'hc2;
		4'h2: LV = 8'h1d;
		4'h3: LV = 8'hb5;
		4'h4: LV = 8'hf9;
		4'h5: LV = 8'hb9;
		4'h6: LV = 8'h27;
		4'h7: LV = 8'h6a;
		4'h8: LV = 8'h4d;
		4'h9: LV = 8'he4;
		4'ha: LV = 8'ha6;
		4'hb: LV = 8'h72;
		4'hc: LV = 8'h9a;
		4'hd: LV = 8'hc9;
		4'he: LV = 8'h09;
		4'hf: LV = 8'h78;
		default: LV = 8'hee;
		endcase
	4'h3:
		case(lmatCol)
		4'h0: LV = 8'h65;
		4'h1: LV = 8'h2f;
		4'h2: LV = 8'h8a;
		4'h3: LV = 8'h05;
		4'h4: LV = 8'h21;
		4'h5: LV = 8'h0f;
		4'h6: LV = 8'he1;
		4'h7: LV = 8'h24;
		4'h8: LV = 8'h12;
		4'h9: LV = 8'hf0;
		4'ha: LV = 8'h82;
		4'hb: LV = 8'h45;
		4'hc: LV = 8'h35;
		4'hd: LV = 8'h93;
		4'he: LV = 8'hda;
		4'hf: LV = 8'h8e;
		default: LV = 8'hee;
		endcase
	4'h4:
		case(lmatCol)
		4'h0: LV = 8'h96;
		4'h1: LV = 8'h8f;
		4'h2: LV = 8'hdb;
		4'h3: LV = 8'hbd;
		4'h4: LV = 8'h36;
		4'h5: LV = 8'hd0;
		4'h6: LV = 8'hce;
		4'h7: LV = 8'h94;
		4'h8: LV = 8'h13;
		4'h9: LV = 8'h5c;
		4'ha: LV = 8'hd2;
		4'hb: LV = 8'hf1;
		4'hc: LV = 8'h40;
		4'hd: LV = 8'h46;
		4'he: LV = 8'h83;
		4'hf: LV = 8'h38;
		default: LV = 8'hee;
		endcase
	4'h5:
		case(lmatCol)
		4'h0: LV = 8'h66;
		4'h1: LV = 8'hdd;
		4'h2: LV = 8'hfd;
		4'h3: LV = 8'h30;
		4'h4: LV = 8'hbf;
		4'h5: LV = 8'h06;
		4'h6: LV = 8'h8b;
		4'h7: LV = 8'h62;
		4'h8: LV = 8'hb3;
		4'h9: LV = 8'h25;
		4'ha: LV = 8'he2;
		4'hb: LV = 8'h98;
		4'hc: LV = 8'h22;
		4'hd: LV = 8'h88;
		4'he: LV = 8'h91;
		4'hf: LV = 8'h10;
		default: LV = 8'hee;
		endcase
	4'h6:
		case(lmatCol)
		4'h0: LV = 8'h7e;
		4'h1: LV = 8'h6e;
		4'h2: LV = 8'h48;
		4'h3: LV = 8'hc3;
		4'h4: LV = 8'ha3;
		4'h5: LV = 8'hb6;
		4'h6: LV = 8'h1e;
		4'h7: LV = 8'h42;
		4'h8: LV = 8'h3a;
		4'h9: LV = 8'h6b;
		4'ha: LV = 8'h28;
		4'hb: LV = 8'h54;
		4'hc: LV = 8'hfa;
		4'hd: LV = 8'h85;
		4'he: LV = 8'h3d;
		4'hf: LV = 8'hba;
		default: LV = 8'hee;
		endcase
	4'h7:
		case(lmatCol)
		4'h0: LV = 8'h2b;
		4'h1: LV = 8'h79;
		4'h2: LV = 8'h0a;
		4'h3: LV = 8'h15;
		4'h4: LV = 8'h9b;
		4'h5: LV = 8'h9f;
		4'h6: LV = 8'h5e;
		4'h7: LV = 8'hca;
		4'h8: LV = 8'h4e;
		4'h9: LV = 8'hd4;
		4'ha: LV = 8'hac;
		4'hb: LV = 8'he5;
		4'hc: LV = 8'hf3;
		4'hd: LV = 8'h73;
		4'he: LV = 8'ha7;
		4'hf: LV = 8'h57;
		default: LV = 8'hee;
		endcase
	4'h8:
		case(lmatCol)
		4'h0: LV = 8'haf;
		4'h1: LV = 8'h58;
		4'h2: LV = 8'ha8;
		4'h3: LV = 8'h50;
		4'h4: LV = 8'hf4;
		4'h5: LV = 8'hea;
		4'h6: LV = 8'hd6;
		4'h7: LV = 8'h74;
		4'h8: LV = 8'h4f;
		4'h9: LV = 8'hae;
		4'ha: LV = 8'he9;
		4'hb: LV = 8'hd5;
		4'hc: LV = 8'he7;
		4'hd: LV = 8'he6;
		4'he: LV = 8'had;
		4'hf: LV = 8'he8;
		default: LV = 8'hee;
		endcase
	4'h9:
		case(lmatCol)
		4'h0: LV = 8'h2c;
		4'h1: LV = 8'hd7;
		4'h2: LV = 8'h75;
		4'h3: LV = 8'h7a;
		4'h4: LV = 8'heb;
		4'h5: LV = 8'h16;
		4'h6: LV = 8'h0b;
		4'h7: LV = 8'hf5;
		4'h8: LV = 8'h59;
		4'h9: LV = 8'hcb;
		4'ha: LV = 8'h5f;
		4'hb: LV = 8'hb0;
		4'hc: LV = 8'h9c;
		4'hd: LV = 8'ha9;
		4'he: LV = 8'h51;
		4'hf: LV = 8'ha0;
		default: LV = 8'hee;
		endcase
	4'ha:
		case(lmatCol)
		4'h0: LV = 8'h7f;
		4'h1: LV = 8'h0c;
		4'h2: LV = 8'hf6;
		4'h3: LV = 8'h6f;
		4'h4: LV = 8'h17;
		4'h5: LV = 8'hc4;
		4'h6: LV = 8'h49;
		4'h7: LV = 8'hec;
		4'h8: LV = 8'hd8;
		4'h9: LV = 8'h43;
		4'ha: LV = 8'h1f;
		4'hb: LV = 8'h2d;
		4'hc: LV = 8'ha4;
		4'hd: LV = 8'h76;
		4'he: LV = 8'h7b;
		4'hf: LV = 8'hb7;
		default: LV = 8'hee;
		endcase
	4'hb:
		case(lmatCol)
		4'h0: LV = 8'hcc;
		4'h1: LV = 8'hbb;
		4'h2: LV = 8'h3e;
		4'h3: LV = 8'h5a;
		4'h4: LV = 8'hfb;
		4'h5: LV = 8'h60;
		4'h6: LV = 8'hb1;
		4'h7: LV = 8'h86;
		4'h8: LV = 8'h3b;
		4'h9: LV = 8'h52;
		4'ha: LV = 8'ha1;
		4'hb: LV = 8'h6c;
		4'hc: LV = 8'haa;
		4'hd: LV = 8'h55;
		4'he: LV = 8'h29;
		4'hf: LV = 8'h9d;
		default: LV = 8'hee;
		endcase
	4'hc:
		case(lmatCol)
		4'h0: LV = 8'h97;
		4'h1: LV = 8'hb2;
		4'h2: LV = 8'h87;
		4'h3: LV = 8'h90;
		4'h4: LV = 8'h61;
		4'h5: LV = 8'hbe;
		4'h6: LV = 8'hdc;
		4'h7: LV = 8'hfc;
		4'h8: LV = 8'hbc;
		4'h9: LV = 8'h95;
		4'ha: LV = 8'hcf;
		4'hb: LV = 8'hcd;
		4'hc: LV = 8'h37;
		4'hd: LV = 8'h3f;
		4'he: LV = 8'h5b;
		4'hf: LV = 8'hd1;
		default: LV = 8'hee;
		endcase
	4'hd:
		case(lmatCol)
		4'h0: LV = 8'h53;
		4'h1: LV = 8'h39;
		4'h2: LV = 8'h84;
		4'h3: LV = 8'h3c;
		4'h4: LV = 8'h41;
		4'h5: LV = 8'ha2;
		4'h6: LV = 8'h6d;
		4'h7: LV = 8'h47;
		4'h8: LV = 8'h14;
		4'h9: LV = 8'h2a;
		4'ha: LV = 8'h9e;
		4'hb: LV = 8'h5d;
		4'hc: LV = 8'h56;
		4'hd: LV = 8'hf2;
		4'he: LV = 8'hd3;
		4'hf: LV = 8'hab;
		default: LV = 8'hee;
		endcase
	4'he:
		case(lmatCol)
		4'h0: LV = 8'h44;
		4'h1: LV = 8'h11;
		4'h2: LV = 8'h92;
		4'h3: LV = 8'hd9;
		4'h4: LV = 8'h23;
		4'h5: LV = 8'h20;
		4'h6: LV = 8'h2e;
		4'h7: LV = 8'h89;
		4'h8: LV = 8'hb4;
		4'h9: LV = 8'h7c;
		4'ha: LV = 8'hb8;
		4'hb: LV = 8'h26;
		4'hc: LV = 8'h77;
		4'hd: LV = 8'h99;
		4'he: LV = 8'he3;
		4'hf: LV = 8'ha5;
		default: LV = 8'hee;
		endcase
	4'hf:
		case(lmatCol)
		4'h0: LV = 8'h67;
		4'h1: LV = 8'h4a;
		4'h2: LV = 8'hed;
		4'h3: LV = 8'hde;
		4'h4: LV = 8'hc5;
		4'h5: LV = 8'h31;
		4'h6: LV = 8'hfe;
		4'h7: LV = 8'h18;
		4'h8: LV = 8'h0d;
		4'h9: LV = 8'h63;
		4'ha: LV = 8'h8c;
		4'hb: LV = 8'h80;
		4'hc: LV = 8'hc0;
		4'hd: LV = 8'hf7;
		4'he: LV = 8'h70;
		4'hf: LV = 8'h07;
		default: LV = 8'hee;
		endcase
	default: LV = 8'hee;
	endcase

//E Table.............................................................case (row)
	case(ematRow)
	4'h0: 
		case(ematCol)
		4'h0: EV = 8'h01; 
		4'h1: EV = 8'h03;
		4'h2: EV = 8'h05;
		4'h3: EV = 8'h0f;
		4'h4: EV = 8'h11;
		4'h5: EV = 8'h33;
		4'h6: EV = 8'h55;
		4'h7: EV = 8'hff;
		4'h8: EV = 8'h1a;
		4'h9: EV = 8'h2e;
		4'ha: EV = 8'h72;
		4'hb: EV = 8'h96;
		4'hc: EV = 8'ha1;
		4'hd: EV = 8'hf8;
		4'he: EV = 8'h13;
		4'hf: EV = 8'h35;
		default: EV = 8'hee;
		endcase
	4'h1:
		case(ematCol)
		4'h0: EV = 8'h5f;
		4'h1: EV = 8'he1;
		4'h2: EV = 8'h38;
		4'h3: EV = 8'h48;
		4'h4: EV = 8'hd8;
		4'h5: EV = 8'h73;
		4'h6: EV = 8'h95;
		4'h7: EV = 8'ha4;
		4'h8: EV = 8'hf7;
		4'h9: EV = 8'h02;
		4'ha: EV = 8'h06;
		4'hb: EV = 8'h0a;
		4'hc: EV = 8'h1e;
		4'hd: EV = 8'h22;
		4'he: EV = 8'h66;
		4'hf: EV = 8'haa;
		default: EV = 8'hee;
		endcase
	4'h2:
		case(ematCol)
		4'h0: EV = 8'he5;
		4'h1: EV = 8'h34;
		4'h2: EV = 8'h5c;
		4'h3: EV = 8'he4;
		4'h4: EV = 8'h37;
		4'h5: EV = 8'h59;
		4'h6: EV = 8'heb;
		4'h7: EV = 8'h26;
		4'h8: EV = 8'h6a;
		4'h9: EV = 8'hbe;
		4'ha: EV = 8'hd9;
		4'hb: EV = 8'h70;
		4'hc: EV = 8'h90;
		4'hd: EV = 8'hab;
		4'he: EV = 8'he6;
		4'hf: EV = 8'h31;
		default: EV = 8'hee;
		endcase
	4'h3:
		case(ematCol)
		4'h0: EV = 8'h53;
		4'h1: EV = 8'hf5;
		4'h2: EV = 8'h04;
		4'h3: EV = 8'h0c;
		4'h4: EV = 8'h14;
		4'h5: EV = 8'h3c;
		4'h6: EV = 8'h44;
		4'h7: EV = 8'hcc;
		4'h8: EV = 8'h4f;
		4'h9: EV = 8'hd1;
		4'ha: EV = 8'h68;
		4'hb: EV = 8'hb8;
		4'hc: EV = 8'hd3;
		4'hd: EV = 8'h6e;
		4'he: EV = 8'hb2;
		4'hf: EV = 8'hcd;
		default: EV = 8'hee;
		endcase
	4'h4:
		case(ematCol)
		4'h0: EV = 8'h4c;
		4'h1: EV = 8'hd4;
		4'h2: EV = 8'h67;
		4'h3: EV = 8'ha9;
		4'h4: EV = 8'he0;
		4'h5: EV = 8'h3b;
		4'h6: EV = 8'h4d;
		4'h7: EV = 8'hd7;
		4'h8: EV = 8'h62;
		4'h9: EV = 8'ha6;
		4'ha: EV = 8'hf1;
		4'hb: EV = 8'h08;
		4'hc: EV = 8'h18;
		4'hd: EV = 8'h28;
		4'he: EV = 8'h78;
		4'hf: EV = 8'h88;
		default: EV = 8'hee;
		endcase
	4'h5:
		case(ematCol)
		4'h0: EV = 8'h83;
		4'h1: EV = 8'h9e;
		4'h2: EV = 8'hb9;
		4'h3: EV = 8'hd0;
		4'h4: EV = 8'h6b;
		4'h5: EV = 8'hbd;
		4'h6: EV = 8'hdc;
		4'h7: EV = 8'h7f;
		4'h8: EV = 8'h81;
		4'h9: EV = 8'h98;
		4'ha: EV = 8'hb3;
		4'hb: EV = 8'hce;
		4'hc: EV = 8'h49;
		4'hd: EV = 8'hdb;
		4'he: EV = 8'h76;
		4'hf: EV = 8'h9a;
		default: EV = 8'hee;
		endcase
	4'h6:
		case(ematCol)
		4'h0: EV = 8'hb5;
		4'h1: EV = 8'hc4;
		4'h2: EV = 8'h57;
		4'h3: EV = 8'hf9;
		4'h4: EV = 8'h10;
		4'h5: EV = 8'h30;
		4'h6: EV = 8'h50;
		4'h7: EV = 8'hf0;
		4'h8: EV = 8'h0b;
		4'h9: EV = 8'h1d;
		4'ha: EV = 8'h27;
		4'hb: EV = 8'h69;
		4'hc: EV = 8'hbb;
		4'hd: EV = 8'hd6;
		4'he: EV = 8'h61;
		4'hf: EV = 8'ha3;
		default: EV = 8'hee;
		endcase
	4'h7:
		case(ematCol)
		4'h0: EV = 8'hfe;
		4'h1: EV = 8'h19;
		4'h2: EV = 8'h2b;
		4'h3: EV = 8'h7d;
		4'h4: EV = 8'h87;
		4'h5: EV = 8'h92;
		4'h6: EV = 8'had;
		4'h7: EV = 8'hec;
		4'h8: EV = 8'h2f;
		4'h9: EV = 8'h71;
		4'ha: EV = 8'h93;
		4'hb: EV = 8'hae;
		4'hc: EV = 8'he9;
		4'hd: EV = 8'h20;
		4'he: EV = 8'h60;
		4'hf: EV = 8'ha0;
		default: EV = 8'hee;
		endcase
	4'h8:
		case(ematCol)
		4'h0: EV = 8'hfb;
		4'h1: EV = 8'h16;
		4'h2: EV = 8'h3a;
		4'h3: EV = 8'h4e;
		4'h4: EV = 8'hd2;
		4'h5: EV = 8'h6d;
		4'h6: EV = 8'hb7;
		4'h7: EV = 8'hc2;
		4'h8: EV = 8'h5d;
		4'h9: EV = 8'he7;
		4'ha: EV = 8'h32;
		4'hb: EV = 8'h56;
		4'hc: EV = 8'hfa;
		4'hd: EV = 8'h15;
		4'he: EV = 8'h3f;
		4'hf: EV = 8'h41;
		default: EV = 8'hee;
		endcase
	4'h9:
		case(ematCol)
		4'h0: EV = 8'hc3;
		4'h1: EV = 8'h5e;
		4'h2: EV = 8'he2;
		4'h3: EV = 8'h3d;
		4'h4: EV = 8'h47;
		4'h5: EV = 8'hc9;
		4'h6: EV = 8'h40;
		4'h7: EV = 8'hc0;
		4'h8: EV = 8'h5b;
		4'h9: EV = 8'hed;
		4'ha: EV = 8'h2c;
		4'hb: EV = 8'h74;
		4'hc: EV = 8'h9c;
		4'hd: EV = 8'hbf;
		4'he: EV = 8'hda;
		4'hf: EV = 8'h75;
		default: EV = 8'hee;
		endcase
	4'ha:
		case(ematCol)
		4'h0: EV = 8'h9f;
		4'h1: EV = 8'hba;
		4'h2: EV = 8'hd5;
		4'h3: EV = 8'h64;
		4'h4: EV = 8'hac;
		4'h5: EV = 8'hef;
		4'h6: EV = 8'h2a;
		4'h7: EV = 8'h7e;
		4'h8: EV = 8'h82;
		4'h9: EV = 8'h9d;
		4'ha: EV = 8'hbc;
		4'hb: EV = 8'hdf;
		4'hc: EV = 8'h7a;
		4'hd: EV = 8'h8e;
		4'he: EV = 8'h89;
		4'hf: EV = 8'h80;
		default: EV = 8'hee;
		endcase
	4'hb:
		case(ematCol)
		4'h0: EV = 8'h9b;
		4'h1: EV = 8'hb6;
		4'h2: EV = 8'hc1;
		4'h3: EV = 8'h58;
		4'h4: EV = 8'he8;
		4'h5: EV = 8'h23;
		4'h6: EV = 8'h65;
		4'h7: EV = 8'haf;
		4'h8: EV = 8'hea;
		4'h9: EV = 8'h25;
		4'ha: EV = 8'h6f;
		4'hb: EV = 8'hb1;
		4'hc: EV = 8'hc8;
		4'hd: EV = 8'h43;
		4'he: EV = 8'hc5;
		4'hf: EV = 8'h54;
		default: EV = 8'hee;
		endcase
	4'hc:
		case(ematCol)
		4'h0: EV = 8'hfc;
		4'h1: EV = 8'h1f;
		4'h2: EV = 8'h21;
		4'h3: EV = 8'h63;
		4'h4: EV = 8'ha5;
		4'h5: EV = 8'hf4;
		4'h6: EV = 8'h07;
		4'h7: EV = 8'h09;
		4'h8: EV = 8'h1b;
		4'h9: EV = 8'h2d;
		4'ha: EV = 8'h77;
		4'hb: EV = 8'h99;
		4'hc: EV = 8'hb0;
		4'hd: EV = 8'hcb;
		4'he: EV = 8'h46;
		4'hf: EV = 8'hca;
		default: EV = 8'hee;
		endcase
	4'hd:
		case(ematCol)
		4'h0: EV = 8'h45;
		4'h1: EV = 8'hcf;
		4'h2: EV = 8'h4a;
		4'h3: EV = 8'hde;
		4'h4: EV = 8'h79;
		4'h5: EV = 8'h8b;
		4'h6: EV = 8'h86;
		4'h7: EV = 8'h91;
		4'h8: EV = 8'ha8;
		4'h9: EV = 8'he3;
		4'ha: EV = 8'h3e;
		4'hb: EV = 8'h42;
		4'hc: EV = 8'hc6;
		4'hd: EV = 8'h51;
		4'he: EV = 8'hf3;
		4'hf: EV = 8'h0e;
		default: EV = 8'hee;
		endcase
	4'he:
		case(ematCol)
		4'h0: EV = 8'h12;
		4'h1: EV = 8'h36;
		4'h2: EV = 8'h5a;
		4'h3: EV = 8'hee;
		4'h4: EV = 8'h29;
		4'h5: EV = 8'h7b;
		4'h6: EV = 8'h8d;
		4'h7: EV = 8'h8c;
		4'h8: EV = 8'h8f;
		4'h9: EV = 8'h8a;
		4'ha: EV = 8'h85;
		4'hb: EV = 8'h94;
		4'hc: EV = 8'ha7;
		4'hd: EV = 8'hf2;
		4'he: EV = 8'h0d;
		4'hf: EV = 8'h17;
		default: EV = 8'hee;
		endcase
	4'hf:
		case(ematCol)
		4'h0: EV = 8'h39;
		4'h1: EV = 8'h4b;
		4'h2: EV = 8'hdd;
		4'h3: EV = 8'h7c;
		4'h4: EV = 8'h84;
		4'h5: EV = 8'h97;
		4'h6: EV = 8'ha2;
		4'h7: EV = 8'hfd;
		4'h8: EV = 8'h1c;
		4'h9: EV = 8'h24;
		4'ha: EV = 8'h6c;
		4'hb: EV = 8'hb4;
		4'hc: EV = 8'hc7;
		4'hd: EV = 8'h52;
		4'he: EV = 8'hf6;
		4'hf: EV = 8'h01;
		default: EV = 8'hee;
		endcase
	default: EV = 8'hee;
	endcase
	
	//Seven segement display on DE2-115 board
	
	
	q[0] = !((!i[0][2] && !i[0][0]) || (!i[0][3] && i[0][2] && i[0][0]) || (!i[0][3] && i[0][1]) || (i[0][2] && i[0][1]) || (i[0][3] && !i[0][0]) || (i[0][3] && !i[0][2] && !i[0][1]));
	r[0] = !((!i[0][2] && !i[0][0]) || (!i[0][3] && !i[0][1] && !i[0][0]) || (!i[0][3] && !i[0][2]) || (!i[0][3] && i[0][1] && i[0][0]) || (i[0][3] && !i[0][1] && i[0][0]));
	s[0] = !((!i[0][3] && !i[0][1]) || (!i[0][1] && i[0][0]) || (!i[0][3] && i[0][0]) || (!i[0][3] && i[0][2]) || (i[0][3] && !i[0][2]));
	t[0] = !((!i[0][3] && !i[0][2] && !i[0][0]) || (i[0][2] && !i[0][1] && i[0][0]) || (!i[0][3] && !i[0][2] && i[0][1]) || (i[0][2] && i[0][1] && !i[0][0]) || (i[0][3] && !i[0][2] && i[0][0]) || (i[0][3] && !i[0][1]));
	u[0] = !((i[0][1] && !i[0][0]) || (i[0][3] && i[0][1]) || (i[0][3] && i[0][2]) || (!i[0][2] && !i[0][1] && !i[0][0]));
	v[0] = !((!i[0][1] && !i[0][0]) || (!i[0][3] && i[0][2] && !i[0][1]) || (i[0][3] && i[0][1]) || (i[0][2] && !i[0][0]) || (i[0][3] && !i[0][2]));
	w[0] = !((!i[0][3] && i[0][2] && !i[0][1]) || (i[0][3] && !i[0][2]) || (i[0][3] && i[0][0]) || (!i[0][2] && i[0][1]) || (i[0][1] && !i[0][0]));
	
	q[1] = !((!i[1][2] && !i[1][0]) || (!i[1][3] && i[1][2] && i[1][0]) || (!i[1][3] && i[1][1]) || (i[1][2] && i[1][1]) || (i[1][3] && !i[1][0]) || (i[1][3] && !i[1][2] && !i[1][1]));
	r[1] = !((!i[1][2] && !i[1][0]) || (!i[1][3] && !i[1][1] && !i[1][0]) || (!i[1][3] && !i[1][2]) || (!i[1][3] && i[1][1] && i[1][0]) || (i[1][3] && !i[1][1] && i[1][0]));
	s[1] = !((!i[1][3] && !i[1][1]) || (!i[1][1] && i[1][0]) || (!i[1][3] && i[1][0]) || (!i[1][3] && i[1][2]) || (i[1][3] && !i[1][2]));
	t[1] = !((!i[1][3] && !i[1][2] && !i[1][0]) || (i[1][2] && !i[1][1] && i[1][0]) || (!i[1][3] && !i[1][2] && i[1][1]) || (i[1][2] && i[1][1] && !i[1][0]) || (i[1][3] && !i[1][2] && i[1][0]) || (i[1][3] && !i[1][1]));
	u[1] = !((i[1][1] && !i[1][0]) || (i[1][3] && i[1][1]) || (i[1][3] && i[1][2]) || (!i[1][2] && !i[1][1] && !i[1][0]));
	v[1] = !((!i[1][1] && !i[1][0]) || (!i[1][3] && i[1][2] && !i[1][1]) || (i[1][3] && i[1][1]) || (i[1][2] && !i[1][0]) || (i[1][3] && !i[1][2]));
	w[1] = !((!i[1][3] && i[1][2] && !i[1][1]) || (i[1][3] && !i[1][2]) || (i[1][3] && i[1][0]) || (!i[1][2] && i[1][1]) || (i[1][1] && !i[1][0]));
	
	q[2] = !((!i[2][2] && !i[2][0]) || (!i[2][3] && i[2][2] && i[2][0]) || (!i[2][3] && i[2][1]) || (i[2][2] && i[2][1]) || (i[2][3] && !i[2][0]) || (i[2][3] && !i[2][2] && !i[2][1]));
	r[2] = !((!i[2][2] && !i[2][0]) || (!i[2][3] && !i[2][1] && !i[2][0]) || (!i[2][3] && !i[2][2]) || (!i[2][3] && i[2][1] && i[2][0]) || (i[2][3] && !i[2][1] && i[2][0]));
	s[2] = !((!i[2][3] && !i[2][1]) || (!i[2][1] && i[2][0]) || (!i[2][3] && i[2][0]) || (!i[2][3] && i[2][2]) || (i[2][3] && !i[2][2]));
	t[2] = !((!i[2][3] && !i[2][2] && !i[2][0]) || (i[2][2] && !i[2][1] && i[2][0]) || (!i[2][3] && !i[2][2] && i[2][1]) || (i[2][2] && i[2][1] && !i[2][0]) || (i[2][3] && !i[2][2] && i[2][0]) || (i[2][3] && !i[2][1]));
	u[2] = !((i[2][1] && !i[2][0]) || (i[2][3] && i[2][1]) || (i[2][3] && i[2][2]) || (!i[2][2] && !i[2][1] && !i[2][0]));
	v[2] = !((!i[2][1] && !i[2][0]) || (!i[2][3] && i[2][2] && !i[2][1]) || (i[2][3] && i[2][1]) || (i[2][2] && !i[2][0]) || (i[2][3] && !i[2][2]));
	w[2] = !((!i[2][3] && i[2][2] && !i[2][1]) || (i[2][3] && !i[2][2]) || (i[2][3] && i[2][0]) || (!i[2][2] && i[2][1]) || (i[2][1] && !i[2][0]));
	
	q[3] = !((!i[3][2] && !i[3][0]) || (!i[3][3] && i[3][2] && i[3][0]) || (!i[3][3] && i[3][1]) || (i[3][2] && i[3][1]) || (i[3][3] && !i[3][0]) || (i[3][3] && !i[3][2] && !i[3][1]));
	r[3] = !((!i[3][2] && !i[3][0]) || (!i[3][3] && !i[3][1] && !i[3][0]) || (!i[3][3] && !i[3][2]) || (!i[3][3] && i[3][1] && i[3][0]) || (i[3][3] && !i[3][1] && i[3][0]));
	s[3] = !((!i[3][3] && !i[3][1]) || (!i[3][1] && i[3][0]) || (!i[3][3] && i[3][0]) || (!i[3][3] && i[3][2]) || (i[3][3] && !i[3][2]));
	t[3] = !((!i[3][3] && !i[3][2] && !i[3][0]) || (i[3][2] && !i[3][1] && i[3][0]) || (!i[3][3] && !i[3][2] && i[3][1]) || (i[3][2] && i[3][1] && !i[3][0]) || (i[3][3] && !i[3][2] && i[3][0]) || (i[3][3] && !i[3][1]));
	u[3] = !((i[3][1] && !i[3][0]) || (i[3][3] && i[3][1]) || (i[3][3] && i[3][2]) || (!i[3][2] && !i[3][1] && !i[3][0]));
	v[3] = !((!i[3][1] && !i[3][0]) || (!i[3][3] && i[3][2] && !i[3][1]) || (i[3][3] && i[3][1]) || (i[3][2] && !i[3][0]) || (i[3][3] && !i[3][2]));
	w[3] = !((!i[3][3] && i[3][2] && !i[3][1]) || (i[3][3] && !i[3][2]) || (i[3][3] && i[3][0]) || (!i[3][2] && i[3][1]) || (i[3][1] && !i[3][0]));
	
	q[4] = !((!i[4][2] && !i[4][0]) || (!i[4][3] && i[4][2] && i[4][0]) || (!i[4][3] && i[4][1]) || (i[4][2] && i[4][1]) || (i[4][3] && !i[4][0]) || (i[4][3] && !i[4][2] && !i[4][1]));
	r[4] = !((!i[4][2] && !i[4][0]) || (!i[4][3] && !i[4][1] && !i[4][0]) || (!i[4][3] && !i[4][2]) || (!i[4][3] && i[4][1] && i[4][0]) || (i[4][3] && !i[4][1] && i[4][0]));
	s[4] = !((!i[4][3] && !i[4][1]) || (!i[4][1] && i[4][0]) || (!i[4][3] && i[4][0]) || (!i[4][3] && i[4][2]) || (i[4][3] && !i[4][2]));
	t[4] = !((!i[4][3] && !i[4][2] && !i[4][0]) || (i[4][2] && !i[4][1] && i[4][0]) || (!i[4][3] && !i[4][2] && i[4][1]) || (i[4][2] && i[4][1] && !i[4][0]) || (i[4][3] && !i[4][2] && i[4][0]) || (i[4][3] && !i[4][1]));
	u[4] = !((i[4][1] && !i[4][0]) || (i[4][3] && i[4][1]) || (i[4][3] && i[4][2]) || (!i[4][2] && !i[4][1] && !i[4][0]));
	v[4] = !((!i[4][1] && !i[4][0]) || (!i[4][3] && i[4][2] && !i[4][1]) || (i[4][3] && i[4][1]) || (i[4][2] && !i[4][0]) || (i[4][3] && !i[4][2]));
	w[4] = !((!i[4][3] && i[4][2] && !i[4][1]) || (i[4][3] && !i[4][2]) || (i[4][3] && i[4][0]) || (!i[4][2] && i[4][1]) || (i[4][1] && !i[4][0]));
	
	q[5] = !((!i[5][2] && !i[5][0]) || (!i[5][3] && i[5][2] && i[5][0]) || (!i[5][3] && i[5][1]) || (i[5][2] && i[5][1]) || (i[5][3] && !i[5][0]) || (i[5][3] && !i[5][2] && !i[5][1]));
	r[5] = !((!i[5][2] && !i[5][0]) || (!i[5][3] && !i[5][1] && !i[5][0]) || (!i[5][3] && !i[5][2]) || (!i[5][3] && i[5][1] && i[5][0]) || (i[5][3] && !i[5][1] && i[5][0]));
	s[5] = !((!i[5][3] && !i[5][1]) || (!i[5][1] && i[5][0]) || (!i[5][3] && i[5][0]) || (!i[5][3] && i[5][2]) || (i[5][3] && !i[5][2]));
	t[5] = !((!i[5][3] && !i[5][2] && !i[5][0]) || (i[5][2] && !i[5][1] && i[5][0]) || (!i[5][3] && !i[5][2] && i[5][1]) || (i[5][2] && i[5][1] && !i[5][0]) || (i[5][3] && !i[5][2] && i[5][0]) || (i[5][3] && !i[5][1]));
	u[5] = !((i[5][1] && !i[5][0]) || (i[5][3] && i[5][1]) || (i[5][3] && i[5][2]) || (!i[5][2] && !i[5][1] && !i[5][0]));
	v[5] = !((!i[5][1] && !i[5][0]) || (!i[5][3] && i[5][2] && !i[5][1]) || (i[5][3] && i[5][1]) || (i[5][2] && !i[5][0]) || (i[5][3] && !i[5][2]));
	w[5] = !((!i[5][3] && i[5][2] && !i[5][1]) || (i[5][3] && !i[5][2]) || (i[5][3] && i[5][0]) || (!i[5][2] && i[5][1]) || (i[5][1] && !i[5][0]));
	
	q[6] = !((!i[6][2] && !i[6][0]) || (!i[6][3] && i[6][2] && i[6][0]) || (!i[6][3] && i[6][1]) || (i[6][2] && i[6][1]) || (i[6][3] && !i[6][0]) || (i[6][3] && !i[6][2] && !i[6][1]));
	r[6] = !((!i[6][2] && !i[6][0]) || (!i[6][3] && !i[6][1] && !i[6][0]) || (!i[6][3] && !i[6][2]) || (!i[6][3] && i[6][1] && i[6][0]) || (i[6][3] && !i[6][1] && i[6][0]));
	s[6] = !((!i[6][3] && !i[6][1]) || (!i[6][1] && i[6][0]) || (!i[6][3] && i[6][0]) || (!i[6][3] && i[6][2]) || (i[6][3] && !i[6][2]));
	t[6] = !((!i[6][3] && !i[6][2] && !i[6][0]) || (i[6][2] && !i[6][1] && i[6][0]) || (!i[6][3] && !i[6][2] && i[6][1]) || (i[6][2] && i[6][1] && !i[6][0]) || (i[6][3] && !i[6][2] && i[6][0]) || (i[6][3] && !i[6][1]));
	u[6] = !((i[6][1] && !i[6][0]) || (i[6][3] && i[6][1]) || (i[6][3] && i[6][2]) || (!i[6][2] && !i[6][1] && !i[6][0]));
	v[6] = !((!i[6][1] && !i[6][0]) || (!i[6][3] && i[6][2] && !i[6][1]) || (i[6][3] && i[6][1]) || (i[6][2] && !i[6][0]) || (i[6][3] && !i[6][2]));
	w[6] = !((!i[6][3] && i[6][2] && !i[6][1]) || (i[6][3] && !i[6][2]) || (i[6][3] && i[6][0]) || (!i[6][2] && i[6][1]) || (i[6][1] && !i[6][0]));

	q[7] = !((!i[7][2] && !i[7][0]) || (!i[7][3] && i[7][2] && i[7][0]) || (!i[7][3] && i[7][1]) || (i[7][2] && i[7][1]) || (i[7][3] && !i[7][0]) || (i[7][3] && !i[7][2] && !i[7][1]));
	r[7] = !((!i[7][2] && !i[7][0]) || (!i[7][3] && !i[7][1] && !i[7][0]) || (!i[7][3] && !i[7][2]) || (!i[7][3] && i[7][1] && i[7][0]) || (i[7][3] && !i[7][1] && i[7][0]));
	s[7] = !((!i[7][3] && !i[7][1]) || (!i[7][1] && i[7][0]) || (!i[7][3] && i[7][0]) || (!i[7][3] && i[7][2]) || (i[7][3] && !i[7][2]));
	t[7] = !((!i[7][3] && !i[7][2] && !i[7][0]) || (i[7][2] && !i[7][1] && i[7][0]) || (!i[7][3] && !i[7][2] && i[7][1]) || (i[7][2] && i[7][1] && !i[7][0]) || (i[7][3] && !i[7][2] && i[7][0]) || (i[7][3] && !i[7][1]));
	u[7] = !((i[7][1] && !i[7][0]) || (i[7][3] && i[7][1]) || (i[7][3] && i[7][2]) || (!i[7][2] && !i[7][1] && !i[7][0]));
	v[7] = !((!i[7][1] && !i[7][0]) || (!i[7][3] && i[7][2] && !i[7][1]) || (i[7][3] && i[7][1]) || (i[7][2] && !i[7][0]) || (i[7][3] && !i[7][2]));
	w[7] = !((!i[7][3] && i[7][2] && !i[7][1]) || (i[7][3] && !i[7][2]) || (i[7][3] && i[7][0]) || (!i[7][2] && i[7][1]) || (i[7][1] && !i[7][0]));
end

always@(posedge clk or negedge rst)
begin
	if(rst == 1'b0)
		i[0] <= 8'h10;
	else
	begin
		if(sevSeg == 2'b00) //shows first row
		begin
			i[0] <= b[0][3]%8'h10;
			i[1] <= b[0][3]/8'h10;
			
			i[2] <= b[0][2]%8'h10;
			i[3] <= b[0][2]/8'h10;
			
			i[4] <= b[0][1]%8'h10;
			i[5] <= b[0][1]/8'h10;
			
			i[6] <= b[0][0]%8'h10;
			i[7] <= b[0][0]/8'h10;
		end
		else if(sevSeg == 2'b01) //shows second row
		begin
			i[0] <= b[1][3]%8'h10;
			i[1] <= b[1][3]/8'h10;
			
			i[2] <= b[1][2]%8'h10;
			i[3] <= b[1][2]/8'h10;
			
			i[4] <= b[1][1]%8'h10;
			i[5] <= b[1][1]/8'h10;
			
			i[6] <= b[1][0]%8'h10;
			i[7] <= b[1][0]/8'h10;
		end
		else if(sevSeg == 2'b10) //shows third row
		begin
			i[0] <= b[2][3]%8'h10;
			i[1] <= b[2][3]/8'h10;
		
			i[2] <= b[2][2]%8'h10;
			i[3] <= b[2][2]/8'h10;
			
			i[4] <= b[2][1]%8'h10;
			i[5] <= b[2][1]/8'h10;
			
			i[6] <= b[2][0]%8'h10;
			i[7] <= b[2][0]/8'h10;
		end
		else if(sevSeg == 2'b11) //shows fourth row
		begin
			i[0] <= b[3][3]%8'h10;
			i[1] <= b[3][3]/8'h10;
			
			i[2] <= b[3][2]%8'h10;
			i[3] <= b[3][2]/8'h10;
			
			i[4] <= b[3][1]%8'h10;
			i[5] <= b[3][1]/8'h10;
			
			i[6] <= b[3][0]%8'h10;
			i[7] <= b[3][0]/8'h10;
		end
		else
		begin
			i[0] <= 8'h00;
			i[1] <= 8'h00;
			
			i[2] <= 8'h00;
			i[3] <= 8'h00;
			
			i[4] <= 8'h00;
			i[5] <= 8'h00;
			
			i[6] <= 8'h00;
			i[7] <= 8'h00;
		end
	end
end
endmodule
