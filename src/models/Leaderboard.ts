import mongoose, { Schema, Document } from 'mongoose';


export interface IPlayer {
    rank: number,
    displayName: string,
    avatarUrl: string,
    userId: string,
    score: number
}

const PlayerSchema = new mongoose.Schema({
    rank: Number,
    displayName: String,
    avatarUrl: String,
    userId: String,
    score: Number
}, {
    _id: false
});


export interface ILeaderBoard<T=any> extends Document {
    id: string,
    players: IPlayer[]
    maxTop: number,
    minTop: number,
    total: number
};

const LeaderBoardSchema: Schema<ILeaderBoard> = new Schema<ILeaderBoard>({
    id:       { type: String, index: { unique: true, sparse: true } },
    players: [PlayerSchema],
    maxTop:      { type: Number, default: 0 },
    minTop:      { type: Number, default: 0 },
    total:       { type: Number, default: 0 },
}, {
    timestamps: true,
});

export default mongoose.model<ILeaderBoard>('LeaderBoard', LeaderBoardSchema);